import { hvt } from '@/lib/hvt';

export function login(data, config = {}) {
    return hvt.auth.login(data, config);
}

export function logout(config = {}) {
    return hvt.auth.logout(config);
}

export function refresh(data = {}, config = {}) {
    return hvt.auth.refresh(data, config);
}

export function register(data, config = {}) {
    return hvt.auth.register(data, config);
}

export function resendVerificationEmail(data, config = {}) {
    return hvt.request('/api/v1/auth/register/resend-email/', {
        method: 'POST',
        body: data,
        auth: 'none',
        ...config,
    });
}

export function getMe(config = {}) {
    return hvt.auth.me(config);
}

export function updateProfile(data, config = {}) {
    return hvt.auth.updateMe(data, config);
}

export function requestPasswordReset(data, config = {}) {
    return hvt.auth.passwordReset(data, config);
}

export function confirmPasswordReset(key, data, config = {}) {
    return hvt.request(`/api/v1/auth/password/reset/confirm/${key}/`, {
        method: 'POST',
        body: data,
        auth: 'none',
        ...config,
    });
}

export function changePassword(data, config = {}) {
    return hvt.auth.passwordChange(data, config);
}

export function socialAuthGoogle(data, config = {}) {
    return hvt.auth.socialGoogle(data, config);
}

export function socialAuthGithub(data, config = {}) {
    return hvt.auth.socialGithub(data, config);
}

export function verifyEmail(key, config = {}) {
    return hvt.request('/api/v1/auth/register/verify-email/', {
        method: 'POST',
        body: { key },
        auth: 'none',
        ...config,
    });
}

export function listSocialProviders(config = {}) {
    return hvt.auth.listSocialProviders(config);
}
