import { hvt } from '@/lib/hvt';

export function createOrg(data, config = {}) {
    return hvt.organizations.create(data, config);
}

export function getCurrentOrg(config = {}) {
    return hvt.organizations.current(config);
}

export function updateOrg(data, config = {}) {
    return hvt.organizations.updateCurrent(data, config);
}

export function listProjects(params = {}, config = {}) {
    return hvt.organizations.listProjects(params, config);
}

export function createProject(data, config = {}) {
    return hvt.organizations.createProject(data, config);
}

export function updateProject(id, data, config = {}) {
    return hvt.organizations.updateProject(id, data, config);
}

export function deleteProject(id, config = {}) {
    return hvt.organizations.deleteProject(id, config);
}

export function listProjectSocialProviders(projectId, config = {}) {
    return hvt.organizations.listProjectSocialProviders(projectId, config);
}

export function createProjectSocialProvider(projectId, data, config = {}) {
    return hvt.organizations.createProjectSocialProvider(projectId, data, config);
}

export function updateProjectSocialProvider(projectId, id, data, config = {}) {
    return hvt.organizations.updateProjectSocialProvider(projectId, id, data, config);
}

export function deleteProjectSocialProvider(projectId, id, config = {}) {
    return hvt.organizations.deleteProjectSocialProvider(projectId, id, config);
}

export function listOrganizationInvitations(params = {}, config = {}) {
    return hvt.organizations.listInvitations(params, config);
}

export function createOrganizationInvitation(data, config = {}) {
    return hvt.organizations.createInvitation(data, config);
}

export function resendOrganizationInvitation(id, config = {}) {
    return hvt.organizations.resendInvitation(id, config);
}

export function revokeOrganizationInvitation(id, config = {}) {
    return hvt.organizations.revokeInvitation(id, config);
}

export function lookupOrganizationInvitation(token, config = {}) {
    return hvt.organizations.lookupInvitation(token, config);
}

export function acceptOrganizationInvitation(token, config = {}) {
    return hvt.organizations.acceptInvitation(token, config);
}

export function getOrgMembers(params = {}, config = {}) {
    return hvt.organizations.listMembers(params, config);
}

export function getPermissions(config = {}) {
    return hvt.organizations.permissions(config);
}
