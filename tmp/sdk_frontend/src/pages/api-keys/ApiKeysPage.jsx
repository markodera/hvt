import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AlertTriangle, KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { createApiKey, listApiKeys, revokeApiKey } from '@/api/apiKeys';
import { listProjects } from '@/api/organizations';
import { createKeySchema } from '@/lib/schemas';
import { formatDate, formatRelativeTime, getErrorMessage } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { CopyButton } from '@/components/CopyButton';

const scopeOptions = [
    { value: 'organization:read', label: 'organization:read' },
    { value: 'users:read', label: 'users:read' },
    { value: 'api_keys:read', label: 'api_keys:read' },
    { value: 'webhooks:read', label: 'webhooks:read' },
    { value: 'audit_logs:read', label: 'audit_logs:read' },
    {
        value: 'auth:runtime',
        label: 'auth:runtime',
        helper: 'Required for runtime login and social auth',
    },
];

function TableCard({ children }) {
    return (
        <section className="overflow-hidden rounded-2xl border border-[#27272a] bg-[#18181b]">
            {children}
        </section>
    );
}

function EmptyState({ message, action }) {
    return (
        <div className="flex min-h-[240px] flex-col items-center justify-center gap-3 px-6 py-10 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[#27272a] bg-[#111111] text-[#71717a]">
                <KeyRound className="h-6 w-6" />
            </div>
            <p className="max-w-md text-sm leading-6 text-[#71717a]">{message}</p>
            {action}
        </div>
    );
}

function SkeletonRow() {
    return (
        <tr className="border-b border-[#27272a] last:border-b-0">
            {Array.from({ length: 6 }).map((_, index) => (
                <td key={index} className="px-4 py-3">
                    <div className="h-5 animate-pulse rounded bg-[#1c1c1f]" />
                </td>
            ))}
        </tr>
    );
}

function Pagination({ count, page, onPageChange, pageSize = 10 }) {
    const totalPages = Math.max(1, Math.ceil((count || 0) / pageSize));
    return (
        <div className="flex flex-col gap-3 border-t border-[#27272a] px-4 py-4 text-sm text-[#71717a] sm:flex-row sm:items-center sm:justify-between">
            <p>
                Page {page} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
                <button
                    type="button"
                    onClick={() => onPageChange(page - 1)}
                    disabled={page <= 1}
                    className="inline-flex h-9 items-center justify-center rounded-md border border-[#27272a] px-3 text-white transition-colors hover:bg-[#111111] disabled:cursor-not-allowed disabled:opacity-40"
                >
                    Previous
                </button>
                <button
                    type="button"
                    onClick={() => onPageChange(page + 1)}
                    disabled={page >= totalPages}
                    className="inline-flex h-9 items-center justify-center rounded-md border border-[#27272a] px-3 text-white transition-colors hover:bg-[#111111] disabled:cursor-not-allowed disabled:opacity-40"
                >
                    Next
                </button>
            </div>
        </div>
    );
}

export default function ApiKeysPage() {
    const queryClient = useQueryClient();
    const [searchParams, setSearchParams] = useSearchParams();
    const [createOpen, setCreateOpen] = useState(false);
    const [revealedKey, setRevealedKey] = useState('');
    const [revokeTarget, setRevokeTarget] = useState(null);

    const page = Number(searchParams.get('page') || 1);
    const projectFilter = searchParams.get('project') || '';

    const { data: projectsData } = useQuery({
        queryKey: ['projects'],
        queryFn: () => listProjects({ page_size: 100 }),
    });

    const projects = useMemo(() => projectsData?.results ?? projectsData ?? [], [projectsData]);

    const { data, isLoading, isError } = useQuery({
        queryKey: ['apiKeys', { page, projectFilter }],
        queryFn: () =>
            listApiKeys({
                page,
                page_size: 10,
                ...(projectFilter ? { project: projectFilter } : {}),
            }),
    });

    const form = useForm({
        resolver: zodResolver(createKeySchema),
        defaultValues: {
            name: '',
            environment: 'test',
            project_id: '',
            scopes: ['auth:runtime'],
            expires_at: null,
        },
    });

    const selectedScopes = form.watch('scopes') || [];

    useEffect(() => {
        if (!projects.length || form.getValues('project_id')) {
            return;
        }
        const defaultProject = projects.find((project) => project.is_default) || projects[0];
        if (defaultProject) {
            form.setValue('project_id', defaultProject.id, { shouldDirty: false });
        }
    }, [form, projects]);

    const createMutation = useMutation({
        mutationFn: createApiKey,
        onSuccess: (createdKey) => {
            queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
            setCreateOpen(false);
            setRevealedKey(createdKey.key);
            form.reset({
                name: '',
                environment: 'test',
                project_id: projects.find((project) => project.is_default)?.id || projects[0]?.id || '',
                scopes: ['auth:runtime'],
                expires_at: null,
            });
            toast.success('API key issued');
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    const revokeMutation = useMutation({
        mutationFn: revokeApiKey,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
            setRevokeTarget(null);
            toast.success('API key revoked');
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    function updateParams(next) {
        const params = new URLSearchParams(searchParams);
        Object.entries(next).forEach(([key, value]) => {
            if (value === '' || value === null || value === undefined) {
                params.delete(key);
            } else {
                params.set(key, String(value));
            }
        });
        setSearchParams(params);
    }

    function handlePageChange(nextPage) {
        updateParams({ page: nextPage });
    }

    function toggleScope(scope) {
        const current = form.getValues('scopes') || [];
        if (current.includes(scope)) {
            form.setValue(
                'scopes',
                current.filter((item) => item !== scope),
                { shouldDirty: true, shouldValidate: true }
            );
            return;
        }

        form.setValue('scopes', [...current, scope], { shouldDirty: true, shouldValidate: true });
    }

    const keys = data?.results ?? [];

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                    <select
                        value={projectFilter}
                        onChange={(event) => updateParams({ project: event.target.value || null, page: 1 })}
                        className="h-10 rounded-md border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                    >
                        <option value="">All projects</option>
                        {projects.map((project) => (
                            <option key={project.id} value={project.id}>
                                {project.name}
                            </option>
                        ))}
                    </select>
                </div>
                <button
                    type="button"
                    onClick={() => setCreateOpen(true)}
                    className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                >
                    <Plus className="h-4 w-4" />
                    Issue new key
                </button>
            </div>

            <TableCard>
                <div className="overflow-x-auto">
                    <table className="min-w-[860px] w-full">
                        <thead>
                            <tr className="border-b border-[#27272a] text-left text-[11px] uppercase tracking-[0.18em] text-[#71717a]">
                                <th className="px-4 py-3 font-medium">Key prefix</th>
                                <th className="px-4 py-3 font-medium">Project</th>
                                <th className="px-4 py-3 font-medium">Created</th>
                                <th className="px-4 py-3 font-medium">Last used</th>
                                <th className="px-4 py-3 font-medium">Status</th>
                                <th className="px-4 py-3 font-medium text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading ? Array.from({ length: 5 }).map((_, index) => <SkeletonRow key={index} />) : null}
                            {!isLoading && isError ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState message="API keys could not be loaded right now." />
                                    </td>
                                </tr>
                            ) : null}
                            {!isLoading && !isError && keys.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState
                                            message="No API keys yet. Issue a project-scoped key to call runtime auth, webhooks, or internal APIs."
                                            action={
                                                <button
                                                    type="button"
                                                    onClick={() => setCreateOpen(true)}
                                                    className="inline-flex h-10 items-center justify-center rounded-md border border-[#7c3aed]/40 px-4 text-sm font-semibold text-[#a78bfa] transition-colors hover:bg-[#111111]"
                                                >
                                                    Issue new key
                                                </button>
                                            }
                                        />
                                    </td>
                                </tr>
                            ) : null}
                            {!isLoading &&
                                !isError &&
                                keys.map((key) => (
                                    <tr key={key.id} className="border-b border-[#27272a] last:border-b-0">
                                        <td className="px-4 py-3">
                                            <p className="font-mono text-sm text-[#a1a1aa]">{key.prefix}...</p>
                                            <p className="mt-1 text-xs text-[#71717a]">{key.name}</p>
                                        </td>
                                        <td className="px-4 py-3">
                                            <p className="text-sm font-medium text-white">{key.project_name || 'Default'}</p>
                                            <p className="mt-1 font-mono text-xs text-[#a78bfa]">{key.project_slug || 'default'}</p>
                                        </td>
                                        <td className="px-4 py-3 font-mono text-xs text-[#71717a]">{formatDate(key.created_at)}</td>
                                        <td className="px-4 py-3 font-mono text-xs text-[#71717a]">
                                            {key.last_used_at ? formatRelativeTime(key.last_used_at) : 'Not used yet'}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="inline-flex items-center gap-2 rounded-full border border-[#27272a] bg-[#111111] px-2.5 py-1 text-xs font-medium text-[#a1a1aa]">
                                                <span className={`h-2 w-2 rounded-full ${key.is_active ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                                                {key.is_active ? 'Active' : 'Revoked'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            {key.is_active ? (
                                                <button
                                                    type="button"
                                                    onClick={() => setRevokeTarget(key)}
                                                    className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 text-sm font-medium text-rose-300 transition-colors hover:bg-rose-500/15"
                                                >
                                                    <Trash2 className="h-4 w-4" />
                                                    Revoke
                                                </button>
                                            ) : (
                                                <span className="text-xs text-[#71717a]">No actions</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>
                </div>

                {data?.count ? <Pagination count={data.count} page={page} onPageChange={handlePageChange} /> : null}
            </TableCard>

            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
                <DialogContent className="max-w-2xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">Issue API key</DialogTitle>
                        <DialogDescription className="text-[#71717a]">
                            Create a project-scoped key for runtime auth or server-to-server access.
                        </DialogDescription>
                    </DialogHeader>

                    <form
                        onSubmit={form.handleSubmit((values) => createMutation.mutate(values))}
                        className="mt-4 space-y-5"
                    >
                        <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-2">
                                <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Project</Label>
                                <select
                                    {...form.register('project_id')}
                                    className="h-10 w-full rounded-md border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                                >
                                    <option value="">Select a project</option>
                                    {projects.map((project) => (
                                        <option key={project.id} value={project.id}>
                                            {project.name}
                                        </option>
                                    ))}
                                </select>
                                {form.formState.errors.project_id ? (
                                    <p className="text-xs text-rose-300">{form.formState.errors.project_id.message}</p>
                                ) : null}
                            </div>

                            <div className="space-y-2">
                                <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Key name</Label>
                                <Input
                                    {...form.register('name')}
                                    placeholder="Storefront runtime"
                                    className="h-10 border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a] focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                                />
                                {form.formState.errors.name ? (
                                    <p className="text-xs text-rose-300">{form.formState.errors.name.message}</p>
                                ) : null}
                            </div>
                        </div>

                        <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-2">
                                <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Environment</Label>
                                <div className="flex flex-wrap gap-2">
                                    {['test', 'live'].map((environment) => (
                                        <button
                                            key={environment}
                                            type="button"
                                            onClick={() => form.setValue('environment', environment, { shouldDirty: true })}
                                            className={`inline-flex h-10 items-center justify-center rounded-md px-4 text-sm font-medium transition-colors ${
                                                form.watch('environment') === environment
                                                    ? 'bg-[#7c3aed] text-white'
                                                    : 'border border-[#27272a] bg-[#18181b] text-[#a1a1aa] hover:bg-[#111111]'
                                            }`}
                                        >
                                            {environment === 'test' ? 'Test' : 'Live'}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Expiry (optional)</Label>
                                <Input
                                    type="datetime-local"
                                    onChange={(event) =>
                                        form.setValue(
                                            'expires_at',
                                            event.target.value ? new Date(event.target.value).toISOString() : null,
                                            { shouldDirty: true }
                                        )
                                    }
                                    className="h-10 border-[#27272a] bg-[#18181b] text-white focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                                />
                            </div>
                        </div>

                        <div className="space-y-3">
                            <div className="flex items-center gap-2">
                                <ShieldCheck className="h-4 w-4 text-[#a78bfa]" />
                                <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Scopes</Label>
                            </div>
                            <div className="grid gap-2 sm:grid-cols-2">
                                {scopeOptions.map((scope) => {
                                    const selected = selectedScopes.includes(scope.value);
                                    return (
                                        <button
                                            key={scope.value}
                                            type="button"
                                            onClick={() => toggleScope(scope.value)}
                                            className={`rounded-xl border px-3 py-3 text-left transition-colors ${
                                                selected
                                                    ? 'border-[#7c3aed]/50 bg-[#7c3aed]/10 text-white'
                                                    : 'border-[#27272a] bg-[#18181b] text-[#a1a1aa] hover:border-[#7c3aed]/30'
                                            }`}
                                        >
                                            <p className="text-sm font-medium">{scope.label}</p>
                                            {scope.helper ? (
                                                <p className="mt-1 text-xs text-[#a78bfa]">{scope.helper}</p>
                                            ) : null}
                                        </button>
                                    );
                                })}
                            </div>
                            {form.formState.errors.scopes ? (
                                <p className="text-xs text-rose-300">{form.formState.errors.scopes.message}</p>
                            ) : null}
                        </div>

                        <DialogFooter className="gap-2 sm:gap-0">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => setCreateOpen(false)}
                                className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                            >
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={createMutation.isPending || selectedScopes.length === 0}
                                className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                            >
                                {createMutation.isPending ? 'Generating...' : 'Generate key'}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>

            <Dialog open={!!revealedKey} onOpenChange={() => setRevealedKey('')}>
                <DialogContent className="max-w-xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">Copy your new key</DialogTitle>
                        <DialogDescription className="flex items-start gap-2 text-[#a1a1aa]">
                            <AlertTriangle className="mt-0.5 h-4 w-4 text-[#a78bfa]" />
                            <span>This key will not be shown again.</span>
                        </DialogDescription>
                    </DialogHeader>
                    <div className="rounded-2xl border border-[#27272a] bg-[#18181b] p-4">
                        <div className="flex items-start justify-between gap-3">
                            <code className="break-all font-mono text-sm text-[#f4f4f5]">{revealedKey}</code>
                            <CopyButton value={revealedKey} />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button onClick={() => setRevealedKey('')} className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]">
                            Done
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <ConfirmDialog
                open={!!revokeTarget}
                onOpenChange={() => setRevokeTarget(null)}
                title="Revoke API key"
                description={`Revoke ${revokeTarget?.name || 'this key'}? This key will stop working immediately.`}
                confirmLabel="Revoke"
                onConfirm={() => revokeMutation.mutate(revokeTarget.id)}
                isLoading={revokeMutation.isPending}
            />
        </div>
    );
}
