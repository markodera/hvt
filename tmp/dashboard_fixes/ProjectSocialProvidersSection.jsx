import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { toast } from 'sonner';
import { Globe2, Pencil, Trash2 } from 'lucide-react';

import {
    listProjectSocialProviders,
    createProjectSocialProvider,
    updateProjectSocialProvider,
    deleteProjectSocialProvider,
} from '@/api/organizations';
import {
    socialProviderCreateSchema,
    socialProviderUpdateSchema,
} from '@/lib/schemas';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogFooter,
    DialogTitle,
    DialogDescription,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { LoadingSpinner } from '@/components/LoadingSpinner';
import { getErrorMessage } from '@/lib/utils';

const selectClassName =
    'flex h-10 w-full rounded-lg border border-[#27272a] bg-[#18181b] px-3 py-2 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25';
const textareaClassName =
    'min-h-[120px] w-full rounded-lg border border-[#27272a] bg-[#18181b] px-3 py-2 text-sm text-white placeholder:text-[#71717a] focus:outline-none focus:ring-2 focus:ring-[#7c3aed]/25';

function serializeRedirectUris(value) {
    return value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
}

function formatProviderLabel(provider) {
    if (provider === 'google') return 'Google';
    if (provider === 'github') return 'GitHub';
    return provider;
}

export function ProjectSocialProvidersSection({ projects }) {
    const queryClient = useQueryClient();
    const [selectedProjectId, setSelectedProjectId] = useState('');
    const [createProviderOpen, setCreateProviderOpen] = useState(false);
    const [editingProvider, setEditingProvider] = useState(null);
    const [deleteProviderTarget, setDeleteProviderTarget] = useState(null);

    const selectedProject = projects.find((project) => project.id === selectedProjectId) || null;

    const { data: socialProviderData, isLoading: socialProvidersLoading } = useQuery({
        queryKey: ['socialProviders', selectedProjectId],
        queryFn: () => listProjectSocialProviders(selectedProjectId),
        enabled: Boolean(selectedProjectId),
    });

    const socialProviders = socialProviderData?.results ?? socialProviderData ?? [];
    const availableProviderOptions = ['google', 'github'].filter(
        (provider) => !socialProviders.some((item) => item.provider === provider)
    );

    const createForm = useForm({
        resolver: zodResolver(socialProviderCreateSchema),
        defaultValues: {
            provider: 'google',
            client_id: '',
            client_secret: '',
            redirect_uris_text: '',
            is_active: true,
        },
    });

    const editForm = useForm({
        resolver: zodResolver(socialProviderUpdateSchema),
        defaultValues: {
            client_id: '',
            client_secret: '',
            redirect_uris_text: '',
            is_active: true,
        },
    });

    useEffect(() => {
        if (!projects.length) {
            if (selectedProjectId) {
                setSelectedProjectId('');
            }
            return;
        }

        const selectedStillExists = projects.some((project) => project.id === selectedProjectId);
        if (!selectedProjectId || !selectedStillExists) {
            const nextProject = projects.find((project) => project.is_default) || projects[0];
            setSelectedProjectId(nextProject.id);
        }
    }, [projects, selectedProjectId]);

    useEffect(() => {
        if (editingProvider) {
            editForm.reset({
                client_id: editingProvider.client_id || '',
                client_secret: '',
                redirect_uris_text: (editingProvider.redirect_uris || []).join('\n'),
                is_active: editingProvider.is_active,
            });
        }
    }, [editingProvider, editForm]);

    const createProviderMutation = useMutation({
        mutationFn: (data) =>
            createProjectSocialProvider(selectedProjectId, {
                ...data,
                redirect_uris: serializeRedirectUris(data.redirect_uris_text),
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['socialProviders'] });
            setCreateProviderOpen(false);
            createForm.reset({
                provider: availableProviderOptions[0] || 'google',
                client_id: '',
                client_secret: '',
                redirect_uris_text: '',
                is_active: true,
            });
            toast.success('Social provider saved');
        },
        onError: (err) => toast.error(getErrorMessage(err)),
    });

    const updateProviderMutation = useMutation({
        mutationFn: ({ projectId, id, data }) =>
            updateProjectSocialProvider(projectId, id, {
                client_id: data.client_id,
                ...(data.client_secret ? { client_secret: data.client_secret } : {}),
                redirect_uris: serializeRedirectUris(data.redirect_uris_text),
                is_active: data.is_active,
            }),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['socialProviders'] });
            setEditingProvider(null);
            toast.success('Social provider updated');
        },
        onError: (err) => toast.error(getErrorMessage(err)),
    });

    const deleteProviderMutation = useMutation({
        mutationFn: ({ projectId, id }) => deleteProjectSocialProvider(projectId, id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['socialProviders'] });
            setDeleteProviderTarget(null);
            toast.success('Social provider deleted');
        },
        onError: (err) => toast.error(getErrorMessage(err)),
    });

    const createProviderActive = createForm.watch('is_active');
    const editProviderActive = editForm.watch('is_active');

    return (
        <>
            <div className="space-y-6 rounded-xl border border-[#27272a] bg-[#111111] p-6">
                <div className="flex items-start justify-between gap-4">
                    <div>
                        <div className="flex items-center gap-2">
                            <Globe2 className="h-5 w-5 text-[#a78bfa]" />
                            <h2 className="text-lg font-bold text-white">Social Providers</h2>
                        </div>
                        <p className="mt-1 text-sm text-[#a1a1aa]">
                            Configure Google and GitHub credentials per project. One project can fail without affecting another.
                        </p>
                    </div>
                    <Button
                        type="button"
                        onClick={() => setCreateProviderOpen(true)}
                        disabled={!selectedProjectId || socialProviders.length >= 2}
                        className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                    >
                        Add provider
                    </Button>
                </div>

                {projects.length > 0 ? (
                    <div className="max-w-sm space-y-2">
                        <Label
                            htmlFor="social-provider-project"
                            className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]"
                        >
                            Project
                        </Label>
                        <select
                            id="social-provider-project"
                            className={selectClassName}
                            value={selectedProjectId}
                            onChange={(event) => setSelectedProjectId(event.target.value)}
                        >
                            {projects.map((project) => (
                                <option key={project.id} value={project.id}>
                                    {project.name}
                                </option>
                            ))}
                        </select>
                    </div>
                ) : (
                    <p className="text-sm text-[#71717a]">Create a project before adding social providers.</p>
                )}

                {selectedProject && (
                    <p className="text-sm text-[#a1a1aa]">
                        Managing provider settings for <span className="font-semibold text-white">{selectedProject.name}</span>
                    </p>
                )}

                {selectedProjectId && socialProvidersLoading && <LoadingSpinner size="sm" />}

                {selectedProjectId && !socialProvidersLoading && socialProviders.length === 0 && (
                    <div className="rounded-xl border border-dashed border-[#27272a] bg-[#18181b] p-4 text-sm text-[#71717a]">
                        No social providers configured for this project yet.
                    </div>
                )}

                <div className="space-y-3">
                    {socialProviders.map((provider) => (
                        <div key={provider.id} className="space-y-3 rounded-xl border border-[#27272a] bg-[#111111] p-4">
                            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                                <div className="space-y-2">
                                    <div className="flex items-center gap-2">
                                        <Badge>{formatProviderLabel(provider.provider)}</Badge>
                                        <Badge variant={provider.is_active ? 'success' : 'warning'}>
                                            {provider.is_active ? 'Active' : 'Inactive'}
                                        </Badge>
                                    </div>
                                    <p className="break-all font-mono text-xs text-[#71717a]">{provider.client_id}</p>
                                    {provider.client_secret_last4 && (
                                        <p className="text-xs text-[#a1a1aa]">Secret ends in {provider.client_secret_last4}</p>
                                    )}
                                </div>
                                <div className="flex gap-2">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="sm"
                                        onClick={() => setEditingProvider({ ...provider, projectId: selectedProjectId })}
                                        className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                                    >
                                        <Pencil className="mr-2 h-4 w-4" />
                                        Edit
                                    </Button>
                                    <Button
                                        type="button"
                                        variant="destructive"
                                        size="sm"
                                        onClick={() => setDeleteProviderTarget({ ...provider, projectId: selectedProjectId })}
                                    >
                                        <Trash2 className="mr-2 h-4 w-4" />
                                        Delete
                                    </Button>
                                </div>
                            </div>
                            <div className="space-y-2">
                                <p className="text-xs font-medium uppercase tracking-wide text-[#71717a]">Redirect URIs</p>
                                {provider.redirect_uris.map((uri) => (
                                    <p key={uri} className="break-all font-mono text-xs text-[#a1a1aa]">
                                        {uri}
                                    </p>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            <Dialog open={createProviderOpen} onOpenChange={setCreateProviderOpen}>
                <DialogContent className="max-w-xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-white">Add social provider</DialogTitle>
                        <DialogDescription className="text-[#a1a1aa]">
                            Attach a Google or GitHub OAuth configuration to the selected project.
                        </DialogDescription>
                    </DialogHeader>
                    <form onSubmit={createForm.handleSubmit((data) => createProviderMutation.mutate(data))} className="mt-4 space-y-4">
                        <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-2">
                                <Label htmlFor="provider" className="text-white">Provider</Label>
                                <select id="provider" className={selectClassName} {...createForm.register('provider')}>
                                    {['google', 'github'].map((provider) => (
                                        <option
                                            key={provider}
                                            value={provider}
                                            disabled={socialProviders.some((item) => item.provider === provider)}
                                        >
                                            {formatProviderLabel(provider)}
                                        </option>
                                    ))}
                                </select>
                                {createForm.formState.errors.provider && (
                                    <p className="text-xs text-danger">{createForm.formState.errors.provider.message}</p>
                                )}
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="provider-client-id" className="text-white">Client ID</Label>
                                <Input
                                    id="provider-client-id"
                                    className="border-[#27272a] bg-[#18181b] text-white"
                                    {...createForm.register('client_id')}
                                />
                                {createForm.formState.errors.client_id && (
                                    <p className="text-xs text-danger">{createForm.formState.errors.client_id.message}</p>
                                )}
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="provider-client-secret" className="text-white">Client secret</Label>
                            <Input
                                id="provider-client-secret"
                                type="password"
                                className="border-[#27272a] bg-[#18181b] text-white"
                                {...createForm.register('client_secret')}
                            />
                            {createForm.formState.errors.client_secret && (
                                <p className="text-xs text-danger">{createForm.formState.errors.client_secret.message}</p>
                            )}
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="provider-redirect-uris" className="text-white">Redirect URIs</Label>
                            <textarea
                                id="provider-redirect-uris"
                                className={textareaClassName}
                                placeholder="One URL per line"
                                {...createForm.register('redirect_uris_text')}
                            />
                            <p className="text-xs text-[#a1a1aa]">
                                Enter one callback URL per line. These must match the URLs allowed by the provider.
                            </p>
                            {createForm.formState.errors.redirect_uris_text && (
                                <p className="text-xs text-danger">{createForm.formState.errors.redirect_uris_text.message}</p>
                            )}
                        </div>

                        <div className="flex items-center justify-between rounded-lg border border-[#27272a] bg-[#111111] px-4 py-3">
                            <div>
                                <p className="text-sm font-medium text-white">Provider active</p>
                                <p className="text-xs text-[#a1a1aa]">
                                    Inactive providers remain saved but are hidden from runtime auth.
                                </p>
                            </div>
                            <button
                                type="button"
                                role="switch"
                                aria-checked={createProviderActive}
                                onClick={() => createForm.setValue('is_active', !createProviderActive, { shouldDirty: true })}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${createProviderActive ? 'bg-[#7c3aed]' : 'border border-[#27272a] bg-[#18181b]'}`}
                            >
                                <span className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${createProviderActive ? 'translate-x-6' : 'translate-x-1'}`} />
                            </button>
                        </div>

                        <DialogFooter>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => setCreateProviderOpen(false)}
                                className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                            >
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={createProviderMutation.isPending || createForm.formState.isSubmitting || !selectedProjectId}
                                className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                            >
                                {createProviderMutation.isPending ? 'Saving...' : 'Save provider'}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>

            <Dialog open={!!editingProvider} onOpenChange={(open) => !open && setEditingProvider(null)}>
                <DialogContent className="max-w-xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-white">Edit social provider</DialogTitle>
                        <DialogDescription className="text-[#a1a1aa]">
                            Update the client ID, redirect URIs, or active status for this provider.
                        </DialogDescription>
                    </DialogHeader>
                    <form onSubmit={editForm.handleSubmit((data) => updateProviderMutation.mutate({ projectId: editingProvider.projectId, id: editingProvider.id, data }))} className="mt-4 space-y-4">
                        <div className="space-y-2">
                            <Label className="text-white">Provider</Label>
                            <Input value={formatProviderLabel(editingProvider?.provider || '')} disabled className="border-[#27272a] bg-[#18181b] text-white" />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="edit-provider-client-id" className="text-white">Client ID</Label>
                            <Input id="edit-provider-client-id" className="border-[#27272a] bg-[#18181b] text-white" {...editForm.register('client_id')} />
                            {editForm.formState.errors.client_id && <p className="text-xs text-danger">{editForm.formState.errors.client_id.message}</p>}
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="edit-provider-client-secret" className="text-white">Client secret</Label>
                            <Input
                                id="edit-provider-client-secret"
                                type="password"
                                placeholder="Leave blank to keep the current secret"
                                className="border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a]"
                                {...editForm.register('client_secret')}
                            />
                            {editingProvider?.client_secret_last4 && (
                                <p className="text-xs text-[#a1a1aa]">Current secret ends in {editingProvider.client_secret_last4}</p>
                            )}
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="edit-provider-redirect-uris" className="text-white">Redirect URIs</Label>
                            <textarea id="edit-provider-redirect-uris" className={textareaClassName} {...editForm.register('redirect_uris_text')} />
                            {editForm.formState.errors.redirect_uris_text && <p className="text-xs text-danger">{editForm.formState.errors.redirect_uris_text.message}</p>}
                        </div>

                        <div className="flex items-center justify-between rounded-lg border border-[#27272a] bg-[#111111] px-4 py-3">
                            <div>
                                <p className="text-sm font-medium text-white">Provider active</p>
                                <p className="text-xs text-[#a1a1aa]">
                                    Inactive providers remain saved but are hidden from runtime auth.
                                </p>
                            </div>
                            <button
                                type="button"
                                role="switch"
                                aria-checked={editProviderActive}
                                onClick={() => editForm.setValue('is_active', !editProviderActive, { shouldDirty: true })}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${editProviderActive ? 'bg-[#7c3aed]' : 'border border-[#27272a] bg-[#18181b]'}`}
                            >
                                <span className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${editProviderActive ? 'translate-x-6' : 'translate-x-1'}`} />
                            </button>
                        </div>

                        <DialogFooter>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => setEditingProvider(null)}
                                className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                            >
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={updateProviderMutation.isPending || editForm.formState.isSubmitting}
                                className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                            >
                                {updateProviderMutation.isPending ? 'Saving...' : 'Save provider'}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>

            <ConfirmDialog
                open={!!deleteProviderTarget}
                onOpenChange={() => setDeleteProviderTarget(null)}
                title="Delete social provider"
                description={`Delete ${formatProviderLabel(deleteProviderTarget?.provider)} from "${selectedProject?.name || 'this project'}"? Runtime social login for this provider will stop working immediately.`}
                confirmLabel="Delete provider"
                onConfirm={() => deleteProviderMutation.mutate({ projectId: deleteProviderTarget.projectId, id: deleteProviderTarget.id })}
                isLoading={deleteProviderMutation.isPending}
            />
        </>
    );
}
