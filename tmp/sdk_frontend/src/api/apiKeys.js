import { hvt } from '@/lib/hvt';

export function listApiKeys(params = {}, config = {}) {
    return hvt.organizations.listApiKeys(params, config);
}

export function createApiKey(data, config = {}) {
    return hvt.organizations.createApiKey(data, config);
}

export function updateApiKey(id, data, config = {}) {
    return hvt.organizations.getApiKey(id, { ...config, query: data });
}

export function revokeApiKey(id, config = {}) {
    return hvt.organizations.revokeApiKey(id, config);
}
