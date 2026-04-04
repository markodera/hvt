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

export function listWebhooks(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listWebhooks(query, requestOptions);
}

export function createWebhook(data, options = {}) {
    return hvt.organizations.createWebhook(data, options);
}

export function getWebhook(id, options = {}) {
    return hvt.organizations.getWebhook(id, options);
}

export function updateWebhook(id, data, options = {}) {
    return hvt.organizations.updateWebhook(id, data, options);
}

export function deleteWebhook(id, options = {}) {
    return hvt.organizations.deleteWebhook(id, options);
}

export function getWebhookDeliveries(id, params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listWebhookDeliveries(id, query, requestOptions);
}
