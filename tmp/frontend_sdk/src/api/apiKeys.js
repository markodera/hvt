import { hvt } from '@/lib/hvt';

function normalizeQueryArgs(params = {}, options = {}) {
    if (
        params &&
        typeof params === 'object' &&
        ('queryKey' in params || 'pageParam' in params || 'meta' in params)
    ) {
        return [{}, params.signal ? { signal: params.signal } : {}];
    }
    return [params, options];
}

export function listApiKeys(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listApiKeys(query, requestOptions);
}

export function createApiKey(data, options = {}) {
    return hvt.organizations.createApiKey(data, options);
}

export function updateApiKey(id, data, options = {}) {
    return hvt.organizations.getApiKey(id, options).then(() =>
        hvt.request(`/api/v1/organizations/current/keys/${id}/`, {
            method: 'PATCH',
            body: data,
            ...options,
        })
    );
}

export function revokeApiKey(id, options = {}) {
    return hvt.organizations.revokeApiKey(id, options);
}
