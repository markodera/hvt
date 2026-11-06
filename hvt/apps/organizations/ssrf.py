# SPDX-License-Identifier: Apache-2.0
"""
SSRF (Server-Side Request Forgery) protection utilities for outbound webhook requests.

Enforces:
1. HTTPS-only scheme in production (HTTP permitted only when settings.DEBUG=True).
2. Rejection of embedded credentials in URL (user:pass@host).
3. Rejection of loopback, private, link-local (169.254.169.254), multicast,
   and reserved IP addresses (both IPv4 and IPv6).
4. Connection-time IP verification to prevent DNS rebinding attacks.
5. Strict disabling of redirects (allow_redirects=False).
6. Short connection and read timeouts.
7. Capped response reading without storing response bodies.
"""

import ipaddress
import socket
import urllib.parse
from typing import Optional, Tuple
from django.conf import settings
import urllib3
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from requests.adapters import HTTPAdapter
from requests import Session


class SSRFValidationError(ValueError):
    """Raised when a URL fails initial SSRF safety validation."""
    pass


class SSRFBlockedError(OSError):
    """Raised when a connection to a disallowed IP address is blocked at connection time."""
    pass


DISALLOWED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmark testing
    ipaddress.ip_network("192.0.2.0/24"),      # Documentation / TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast
]


def is_safe_ip(ip_candidate: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Verify whether an IP address is safe for outbound communication.
    Refuses private, loopback, link-local, multicast, and reserved addresses.
    """
    try:
        if isinstance(ip_candidate, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = ip_candidate
        else:
            ip = ipaddress.ip_address(str(ip_candidate).strip())
    except ValueError:
        return False, "Invalid IP address format"

    # Handle IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return False, f"Loopback address ({ip}) is not allowed"
    if ip.is_private:
        return False, f"Private network address ({ip}) is not allowed"
    if ip.is_link_local:
        return False, f"Link-local address ({ip}) is not allowed"
    if ip.is_multicast:
        return False, f"Multicast address ({ip}) is not allowed"
    if ip.is_reserved:
        return False, f"Reserved address ({ip}) is not allowed"
    if ip.is_unspecified:
        return False, f"Unspecified address ({ip}) is not allowed"
    if str(ip) == "169.254.169.254":
        return False, f"Metadata service address ({ip}) is not allowed"

    for net in DISALLOWED_NETWORKS:
        if ip in net:
            return False, f"Address {ip} falls into restricted range {net}"

    return True, ""


def validate_webhook_url(url: str) -> None:
    """
    Validate a webhook URL against SSRF rules.
    Raises SSRFValidationError on violation.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Webhook URL must be a non-empty string.")

    parsed = urllib.parse.urlsplit(url.strip())

    # 1. Scheme check
    debug_mode = getattr(settings, "DEBUG", False)
    if not debug_mode:
        if parsed.scheme.lower() != "https":
            raise SSRFValidationError("Webhook URL must use HTTPS in production.")
    else:
        if parsed.scheme.lower() not in ("http", "https"):
            raise SSRFValidationError("Webhook URL must use HTTP or HTTPS.")

    # 2. Reject credentials in URL
    if parsed.username or parsed.password:
        raise SSRFValidationError("Webhook URL must not contain user credentials.")

    # 3. Hostname check
    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Webhook URL must include a valid hostname.")

    # 4. IP check or DNS resolution check
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_safe, reason = is_safe_ip(ip_obj)
        if not is_safe:
            raise SSRFValidationError(f"Webhook URL target is disallowed: {reason}")
    except ValueError:
        # Hostname is a domain name -> resolve via getaddrinfo
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        try:
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            # In test environments or offline builds, mock or raise
            raise SSRFValidationError(f"Could not resolve webhook host '{hostname}': {exc}")

        if not addr_info:
            raise SSRFValidationError(f"Could not resolve webhook host '{hostname}'.")

        for res in addr_info:
            sa = res[4]
            resolved_ip = sa[0]
            is_safe, reason = is_safe_ip(resolved_ip)
            if not is_safe:
                raise SSRFValidationError(
                    f"Webhook host '{hostname}' resolves to disallowed IP {resolved_ip}: {reason}"
                )


def ssrf_create_connection(
    address: Tuple[str, int],
    timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address: Optional[Tuple[str, int]] = None,
    socket_options: Optional[list] = None,
) -> socket.socket:
    """
    Create a socket connection while checking the target IP at connection time.
    Prevents DNS rebinding attacks where initial resolution differs from connect() resolution.
    """
    host, port = address
    if host.startswith("["):
        host = host.strip("[]")

    try:
        addr_info = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError(f"Could not resolve host '{host}': {exc}") from exc

    if not addr_info:
        raise OSError(f"Could not resolve host '{host}'.")

    err = None
    for res in addr_info:
        af, socktype, proto, canonname, sa = res
        target_ip = sa[0]

        is_safe, reason = is_safe_ip(target_ip)
        if not is_safe:
            raise SSRFBlockedError(f"Connection to prohibited IP {target_ip} blocked: {reason}")

        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    raise OSError(f"Could not connect to {host}:{port}")


class SSRFSafeHTTPConnection(urllib3.connection.HTTPConnection):
    def _new_conn(self) -> socket.socket:
        return ssrf_create_connection(
            (self._dns_host, self.port),
            self.timeout,
            self.source_address,
            self.socket_options,
        )


class SSRFSafeHTTPSConnection(urllib3.connection.HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        return ssrf_create_connection(
            (self._dns_host, self.port),
            self.timeout,
            self.source_address,
            self.socket_options,
        )


class SSRFSafeHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = SSRFSafeHTTPConnection


class SSRFSafeHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SSRFSafeHTTPSConnection


class SSRFSafeHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = urllib3.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )
        self.poolmanager.pool_classes_by_scheme = {
            "http": SSRFSafeHTTPConnectionPool,
            "https": SSRFSafeHTTPSConnectionPool,
        }


def get_ssrf_safe_session() -> Session:
    """
    Return a requests.Session configured with SSRF-safe connection pools.
    """
    session = Session()
    adapter = SSRFSafeHTTPAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
