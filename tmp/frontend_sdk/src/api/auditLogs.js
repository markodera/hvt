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

export function listAuditLogs(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listAuditLogs(query, requestOptions);
}

export function getAuditLog(id, options = {}) {
    return hvt.organizations.getAuditLog(id, options);
}
