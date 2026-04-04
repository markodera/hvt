import { hvt } from '@/lib/hvt';

export function listAuditLogs(params = {}, config = {}) {
    return hvt.organizations.listAuditLogs(params, config);
}

export function getAuditLog(id, config = {}) {
    return hvt.organizations.getAuditLog(id, config);
}
