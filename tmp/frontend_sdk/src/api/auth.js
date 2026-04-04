import { hvt } from '@/lib/hvt';

function normalizeOptions(options = {}) {
    if (
        options &&
        typeof options === 'object' &&
        ('queryKey' in options || 'pageParam' in options || 'meta' in options)
    ) {
        return options.signal ? { signal: options.signal } : {};
    }
    return options;
}

export function login(data, options = {}) {
    return hvt.auth.login(data, options);
}

export function logout(options = {}) {
    return hvt.auth.logout(options);
}

export function register(data, options = {}) {
    return hvt.auth.register(data, options);
}

export function resendVerificationEmail(data, options = {}) {
    return hvt.request('/api/v1/auth/register/resend-email/', {
        method: 'POST',
        body: data,
        auth: 'none',
        ...options,
    });
}

export function getMe(options = {}) {
    return hvt.auth.me(options);
}

export function updateProfile(data, options = {}) {
    return hvt.auth.updateMe(data, options);
}

export function refreshAuth(data = {}, options = {}) {
    return hvt.auth.refresh(data, options);
}

export function requestPasswordReset(data, options = {}) {
    return hvt.auth.passwordReset(data, options);
}

function resolveResetTokenPath(tokenOrKey) {
    if (typeof tokenOrKey === 'string') {
        return tokenOrKey;
    }

    const uid = tokenOrKey?.uid || tokenOrKey?.uidb64;
    const token = tokenOrKey?.token;
    return uid && token ? `${uid}/${token}` : '';
}

export function validatePasswordResetToken(data, options = {}) {
    return hvt.request('/api/v1/auth/password/reset/validate/', {
        method: 'POST',
        body: data,
        auth: 'none',
        ...options,
    });
}

export function confirmPasswordReset(tokenOrKey, data, options = {}) {
    const path = resolveResetTokenPath(tokenOrKey);
    const uid = tokenOrKey?.uid || tokenOrKey?.uidb64;
    const token = tokenOrKey?.token;
    return hvt.request(`/api/v1/auth/password/reset/confirm/${path}/`, {
        method: 'POST',
        body: {
            ...data,
            ...(uid && token ? { uid, token } : {}),
        },
        auth: 'none',
        ...options,
    });
}

export function changePassword(data, options = {}) {
    return hvt.auth.passwordChange(data, options);
}

export function socialAuthGoogle(data, options = {}) {
    return hvt.auth.socialGoogle(data, options);
}

export function socialAuthGithub(data, options = {}) {
    return hvt.auth.socialGithub(data, options);
}

export function verifyEmail(key, options = {}) {
    return hvt.request('/api/v1/auth/register/verify-email/', {
        method: 'POST',
        body: { key },
        auth: 'none',
        ...options,
    });
}

export function listSocialProviders(options = {}) {
    return hvt.auth.listSocialProviders(normalizeOptions(options));
}
