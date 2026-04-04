import { hvt } from '@/lib/hvt';

export function listUsers(params = {}, config = {}) {
    return hvt.users.list(params, config);
}

export function getUser(id, config = {}) {
    return hvt.users.get(id, config);
}

export function updateUserRole(id, data, config = {}) {
    return hvt.users.updateRole(id, data, config);
}
