"""
Pagination classes for HVT API.

* StandardPagination  – page-number based, used as the global default.
* LargeResultPagination – for endpoints expected to return many rows (audit logs).
"""

from rest_framework.pagination import PageNumberPagination, CursorPagination


class StandardPagination(PageNumberPagination):
    """
    Default pagination: 25 items per page, client may request up to 100.

    Query params:
        ?page=2
        ?page_size=50
    """

    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100


class LargeResultPagination(PageNumberPagination):
    """
    For high-volume endpoints (e.g. audit logs, webhook deliveries).

    Query params:
        ?page=2
        ?page_size=100
    """

    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 250


class AuditLogCursorPagination(CursorPagination):
    """
    Cursor-based pagination for audit logs – efficient for very large tables
    and prevents page-drift when new rows are inserted.

    Query params:
        ?cursor=<opaque>
    """

    page_size = 50
    ordering = "-created_at"
    page_size_query_param = "page_size"
    max_page_size = 250
