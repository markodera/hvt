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

export function listUsers(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.users.list(query, requestOptions);
}

export function getUser(id, options = {}) {
    return hvt.users.get(id, options);
}

export function createUser(data, options = {}) {
    return hvt.users.create(data, options);
}

export function updateUser(id, data, options = {}) {
    return hvt.users.update(id, data, options);
}

export function deleteUser(id, options = {}) {
    return hvt.users.delete(id, options);
}

export function updateUserRole(id, data, options = {}) {
    return hvt.users.updateRole(id, data?.role ?? data, options);
}
