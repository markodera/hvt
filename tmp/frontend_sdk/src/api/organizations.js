import { hvt } from '@/lib/hvt';

function normalizeOptions(options = {}) {
    if (
        options &&
        typeof options === 'object' &&
        ('queryKey' in options || 'pageParam' in options || 'meta' in options)
    ) {
        return options.signal ? { signal: options.signal } : {};
    }
    return options;
}

function normalizeQueryArgs(params = {}, options = {}) {
    if (
        params &&
        typeof params === 'object' &&
        ('queryKey' in params || 'pageParam' in params || 'meta' in params)
    ) {
        return [{}, normalizeOptions(params)];
    }
    return [params, normalizeOptions(options)];
}

export function createOrg(data, options = {}) {
    return hvt.organizations.create(data, options);
}

export function getCurrentOrg(options = {}) {
    return hvt.organizations.current(normalizeOptions(options));
}

export function updateOrg(data, options = {}) {
    return hvt.organizations.updateCurrent(data, options);
}

export function listProjects(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listProjects(query, requestOptions);
}

export function createProject(data, options = {}) {
    return hvt.organizations.createProject(data, options);
}

export function updateProject(id, data, options = {}) {
    return hvt.organizations.updateProject(id, data, options);
}

export function deleteProject(id, options = {}) {
    return hvt.organizations.deleteProject(id, options);
}

export function listProjectSocialProviders(projectId, options = {}) {
    return hvt.organizations.listProjectSocialProviders(projectId, options);
}

export function createProjectSocialProvider(projectId, data, options = {}) {
    return hvt.organizations.createProjectSocialProvider(projectId, data, options);
}

export function updateProjectSocialProvider(projectId, id, data, options = {}) {
    return hvt.organizations.updateProjectSocialProvider(projectId, id, data, options);
}

export function deleteProjectSocialProvider(projectId, id, options = {}) {
    return hvt.organizations.deleteProjectSocialProvider(projectId, id, options);
}

export function listOrganizationInvitations(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listInvitations(query, requestOptions);
}

export function createOrganizationInvitation(data, options = {}) {
    return hvt.organizations.createInvitation(data, options);
}

export function resendOrganizationInvitation(id, options = {}) {
    return hvt.organizations.resendInvitation(id, options);
}

export function revokeOrganizationInvitation(id, options = {}) {
    return hvt.organizations.revokeInvitation(id, options);
}

export function lookupOrganizationInvitation(token, options = {}) {
    return hvt.organizations.lookupInvitation(token, options);
}

export function acceptOrganizationInvitation(token, options = {}) {
    return hvt.organizations.acceptInvitation(token, options);
}

export function getOrgMembers(params = {}, options = {}) {
    const [query, requestOptions] = normalizeQueryArgs(params, options);
    return hvt.organizations.listMembers(query, requestOptions);
}

export function getPermissions(options = {}) {
    return hvt.organizations.permissions(normalizeOptions(options));
}
