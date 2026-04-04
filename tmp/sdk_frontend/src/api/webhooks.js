import { hvt } from '@/lib/hvt';

export function listWebhooks(params = {}, config = {}) {
    return hvt.organizations.listWebhooks(params, config);
}

export function createWebhook(data, config = {}) {
    return hvt.organizations.createWebhook(data, config);
}

export function getWebhook(id, config = {}) {
    return hvt.organizations.getWebhook(id, config);
}

export function updateWebhook(id, data, config = {}) {
    return hvt.organizations.updateWebhook(id, data, config);
}

export function deleteWebhook(id, config = {}) {
    return hvt.organizations.deleteWebhook(id, config);
}

export function getWebhookDeliveries(id, params = {}, config = {}) {
    return hvt.organizations.listWebhookDeliveries(id, params, config);
}
