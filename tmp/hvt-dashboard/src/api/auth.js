import client from './client';

export function login(data, config = {}) {
    return client.post('/auth/login/', data, config).then((res) => res.data);
}

export function logout() {
    return client.post('/auth/logout/').then((res) => res.data);
}

export function register(data) {
    return client.post('/auth/register/', data).then((res) => res.data);
}

export function resendVerificationEmail(data) {
    return client.post('/auth/register/resend-email/', data).then((res) => res.data);
}

export function getMe(config = {}) {
    return client.get('/auth/me/', config).then((res) => res.data);
}

export function updateProfile(data) {
    return client.patch('/auth/me/', data).then((res) => res.data);
}

export function requestPasswordReset(data) {
    return client.post('/auth/password/reset/', data).then((res) => res.data);
}

export function validatePasswordResetToken(data) {
    return client.post('/auth/password/reset/validate/', data).then((res) => res.data);
}

export function confirmPasswordReset(keyOrTokens, data) {
    if (typeof keyOrTokens === 'string') {
        return client.post(`/auth/password/reset/confirm/${keyOrTokens}/`, data).then((res) => res.data);
    }

    const { uid, token } = keyOrTokens;
    return client
        .post(`/auth/password/reset/confirm/${uid}/${token}/`, data)
        .then((res) => res.data);
}

export function changePassword(data) {
    return client.post('/auth/password/change/', data).then((res) => res.data);
}

export function socialAuthGoogle(data) {
    return client.post('/auth/social/google/', data).then((res) => res.data);
}

export function socialAuthGithub(data) {
    return client.post('/auth/social/github/', data).then((res) => res.data);
}

export function verifyEmail(key) {
    return client.post('/auth/register/verify-email/', { key }).then((res) => res.data);
}

export function listSocialProviders() {
    return client.get('/auth/social/providers/').then((res) => res.data);
}

