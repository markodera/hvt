import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

import { createApiKey, listApiKeys, revokeApiKey } from '@/api/apiKeys';
import { listProjects } from '@/api/organizations';
import { CopyButton } from '@/components/CopyButton';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { API_KEY_CANONICAL_SCOPES } from '@/lib/hvt';
import { formatDate, formatRelativeTime, getErrorMessage } from '@/lib/utils';

const scopeMeta = {
    'organization:read': {
        label: 'organization:read',
        description: 'Read current organization details.',
    },
    'users:read': {
        label: 'users:read',
        description: 'List users and members in the current organization.',
    },
    'api_keys:read': {
        label: 'api_keys:read',
        description: 'Read issued API keys and their metadata.',
    },
    'webhooks:read': {
        label: 'webhooks:read',
        description: 'Read webhook endpoints and delivery logs.',
    },
    'audit_logs:read': {
        label: 'audit_logs:read',
        description: 'Read audit activity for the current organization.',
    },
    'auth:runtime': {
        label: 'auth:runtime',
        description: 'Required for runtime login and social auth.',
    },
};

function TableCard({ children }) {
    return <section className="overflow-hidden rounded-2xl border border-[#27272a] bg-[#18181b]">{children}</section>;
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
                <td key={index} className="px-4 py-4">
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

function buildInitialDraft(projectId = '') {
    return {
        name: '',
        environment: 'test',
        expires_at: '',
        project_id: projectId,
        scopes: ['auth:runtime'],
    };
}

export default function ApiKeysPage() {
    const queryClient = useQueryClient();
    const [searchParams, setSearchParams] = useSearchParams();
    const [page, setPage] = useState(Number(searchParams.get('page') || 1));
    const [projectFilter, setProjectFilter] = useState(searchParams.get('project') || '');
    const [createOpen, setCreateOpen] = useState(false);
    const [revokeTarget, setRevokeTarget] = useState(null);
    const [createdKey, setCreatedKey] = useState(null);

    const projectsQuery = useQuery({
        queryKey: ['projects', { page_size: 100 }],
        queryFn: () => listProjects({ page_size: 100 }),
    });

    const projects = projectsQuery.data?.results ?? [];
    const defaultProjectId = useMemo(
        () => projects.find((project) => project.is_default)?.id || projects[0]?.id || '',
        [projects]
    );

    const [draft, setDraft] = useState(() => buildInitialDraft(''));

    const apiKeysQuery = useQuery({
        queryKey: ['apiKeys', { page, project: projectFilter || null }],
        queryFn: () =>
            listApiKeys({
                page,
                page_size: 10,
                ...(projectFilter ? { project: projectFilter } : {}),
            }),
    });

    const createMutation = useMutation({
        mutationFn: createApiKey,
        onSuccess: (response) => {
            queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
            setCreatedKey(response);
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

    const keys = apiKeysQuery.data?.results ?? [];

    function syncSearchParams(nextProject, nextPage) {
        const params = new URLSearchParams(searchParams);
        if (nextProject) {
            params.set('project', nextProject);
        } else {
            params.delete('project');
        }
        if (nextPage > 1) {
            params.set('page', String(nextPage));
        } else {
            params.delete('page');
        }
        setSearchParams(params);
    }

    function updateProjectFilter(value) {
        setProjectFilter(value);
        setPage(1);
        syncSearchParams(value, 1);
    }

    function updatePage(nextPage) {
        setPage(nextPage);
        syncSearchParams(projectFilter, nextPage);
    }

    function openCreateDialog() {
        setCreatedKey(null);
        setDraft(buildInitialDraft(defaultProjectId));
        setCreateOpen(true);
    }

    function closeCreateDialog() {
        setCreateOpen(false);
        window.setTimeout(() => {
            setCreatedKey(null);
            setDraft(buildInitialDraft(defaultProjectId));
        }, 120);
    }

    function toggleScope(scope) {
        setDraft((current) => {
            const exists = current.scopes.includes(scope);
            return {
                ...current,
                scopes: exists
                    ? current.scopes.filter((item) => item !== scope)
                    : [...current.scopes, scope],
            };
        });
    }

    function submitCreate(event) {
        event.preventDefault();

        if (!draft.project_id) {
            toast.error('Select a project for this key.');
            return;
        }

        if (!draft.scopes.length) {
            toast.error('Select at least one scope.');
            return;
        }

        createMutation.mutate({
            name: draft.name.trim(),
            environment: draft.environment,
            project_id: draft.project_id,
            scopes: draft.scopes,
            expires_at: draft.expires_at || null,
        });
    }

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                    <select
                        value={projectFilter}
                        onChange={(event) => updateProjectFilter(event.target.value)}
                        className="h-10 min-w-[220px] rounded-md border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
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
                    onClick={openCreateDialog}
                    className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                >
                    <Plus className="h-4 w-4" />
                    Issue new key
                </button>
            </div>

            <TableCard>
                <div className="overflow-x-auto">
                    <table className="min-w-[980px] w-full">
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
                            {apiKeysQuery.isLoading ? Array.from({ length: 6 }).map((_, index) => <SkeletonRow key={index} />) : null}
                            {!apiKeysQuery.isLoading && apiKeysQuery.isError ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState message="API keys could not be loaded right now." />
                                    </td>
                                </tr>
                            ) : null}
                            {!apiKeysQuery.isLoading && !apiKeysQuery.isError && keys.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState
                                            message="No API keys yet. Issue a project-scoped key to connect your backend runtime to HVT."
                                            action={
                                                <button
                                                    type="button"
                                                    onClick={openCreateDialog}
                                                    className="inline-flex h-10 items-center justify-center rounded-md border border-[#7c3aed]/40 px-4 text-sm font-semibold text-[#a78bfa] transition-colors hover:bg-[#111111]"
                                                >
                                                    Issue new key
                                                </button>
                                            }
                                        />
                                    </td>
                                </tr>
                            ) : null}
                            {!apiKeysQuery.isLoading &&
                                !apiKeysQuery.isError &&
                                keys.map((apiKey) => (
                                    <tr key={apiKey.id} className="border-b border-[#27272a] last:border-b-0">
                                        <td className="px-4 py-4">
                                            <div className="font-mono text-sm text-white">{apiKey.prefix}...</div>
                                            <div className="mt-1 text-xs text-[#71717a]">{apiKey.name}</div>
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="text-sm text-white">{apiKey.project_name || 'Default project'}</div>
                                            <div className="mt-1 inline-flex rounded-full border border-[#7c3aed]/30 bg-[#7c3aed]/10 px-2 py-1 font-mono text-[11px] text-[#c4b5fd]">
                                                {apiKey.project_slug || 'default'}
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 font-mono text-xs text-[#71717a]">{formatDate(apiKey.created_at)}</td>
                                        <td className="px-4 py-4 font-mono text-xs text-[#71717a]">
                                            {apiKey.last_used_at ? formatRelativeTime(apiKey.last_used_at) : 'Never'}
                                        </td>
                                        <td className="px-4 py-4">
                                            <div className="flex items-center gap-2">
                                                <span className={`h-2 w-2 rounded-full ${apiKey.is_active ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                                                <span className="text-sm text-[#a1a1aa]">{apiKey.is_active ? 'Active' : 'Revoked'}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 text-right">
                                            <button
                                                type="button"
                                                onClick={() => setRevokeTarget(apiKey)}
                                                disabled={!apiKey.is_active}
                                                className="inline-flex h-9 items-center justify-center rounded-md border border-rose-500/30 bg-rose-500/10 px-3 text-sm font-medium text-rose-300 transition-colors hover:bg-rose-500/15 disabled:cursor-not-allowed disabled:opacity-50"
                                            >
                                                <Trash2 className="mr-2 h-4 w-4" />
                                                Revoke
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>
                </div>

                {apiKeysQuery.data?.count ? <Pagination count={apiKeysQuery.data.count} page={page} onPageChange={updatePage} /> : null}
            </TableCard>

            <Dialog open={createOpen} onOpenChange={(open) => (open ? setCreateOpen(true) : closeCreateDialog())}>
                <DialogContent className="max-w-3xl border-[#27272a] bg-[#111111] text-white">
                    {!createdKey ? (
                        <>
                            <DialogHeader>
                                <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">Issue new API key</DialogTitle>
                                <DialogDescription className="text-[#71717a]">
                                    Create a project-scoped key for server-side integration. Choose only the scopes the runtime needs.
                                </DialogDescription>
                            </DialogHeader>

                            <form onSubmit={submitCreate} className="mt-4 space-y-5">
                                <div className="grid gap-5 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Project</Label>
                                        <select
                                            value={draft.project_id}
                                            onChange={(event) => setDraft((current) => ({ ...current, project_id: event.target.value }))}
                                            className="h-10 w-full rounded-md border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                                            required
                                        >
                                            <option value="">Select a project</option>
                                            {projects.map((project) => (
                                                <option key={project.id} value={project.id}>
                                                    {project.name}
                                                </option>
                                            ))}
                                        </select>
                                    </div>

                                    <div className="space-y-2">
                                        <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Environment</Label>
                                        <select
                                            value={draft.environment}
                                            onChange={(event) => setDraft((current) => ({ ...current, environment: event.target.value }))}
                                            className="h-10 w-full rounded-md border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                                        >
                                            <option value="test">Test</option>
                                            <option value="live">Live</option>
                                        </select>
                                    </div>
                                </div>

                                <div className="grid gap-5 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Key name</Label>
                                        <Input
                                            value={draft.name}
                                            onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
                                            placeholder="Storefront runtime"
                                            className="h-10 border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a] focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                                            required
                                        />
                                    </div>

                                    <div className="space-y-2">
                                        <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Expiry (optional)</Label>
                                        <Input
                                            type="datetime-local"
                                            value={draft.expires_at}
                                            onChange={(event) => setDraft((current) => ({ ...current, expires_at: event.target.value }))}
                                            className="h-10 border-[#27272a] bg-[#18181b] text-white focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                                        />
                                    </div>
                                </div>

                                <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                        <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Scopes</Label>
                                        {!draft.scopes.length ? (
                                            <span className="text-xs text-rose-300">Select at least one scope.</span>
                                        ) : null}
                                    </div>
                                    <div className="grid gap-3 md:grid-cols-2">
                                        {API_KEY_CANONICAL_SCOPES.map((scope) => {
                                            const selected = draft.scopes.includes(scope);
                                            const meta = scopeMeta[scope];
                                            return (
                                                <button
                                                    key={scope}
                                                    type="button"
                                                    onClick={() => toggleScope(scope)}
                                                    className={`rounded-xl border px-4 py-3 text-left transition-colors ${
                                                        selected
                                                            ? 'border-[#7c3aed]/50 bg-[#7c3aed]/10 text-white'
                                                            : 'border-[#27272a] bg-[#18181b] text-[#a1a1aa] hover:border-[#7c3aed]/30'
                                                    }`}
                                                >
                                                    <div className="flex items-start gap-3">
                                                        <div className={`mt-0.5 flex h-5 w-5 items-center justify-center rounded border ${selected ? 'border-[#7c3aed] bg-[#7c3aed]' : 'border-[#3f3f46] bg-[#111111]'}`}>
                                                            {selected ? <ShieldCheck className="h-3.5 w-3.5 text-white" /> : null}
                                                        </div>
                                                        <div>
                                                            <p className="font-mono text-sm text-white">{meta.label}</p>
                                                            <p className="mt-1 text-xs leading-5 text-[#71717a]">{meta.description}</p>
                                                        </div>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>

                                <DialogFooter>
                                    <Button
                                        type="button"
                                        variant="outline"
                                        onClick={closeCreateDialog}
                                        className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        type="submit"
                                        disabled={createMutation.isPending || !draft.scopes.length}
                                        className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                                    >
                                        {createMutation.isPending ? 'Generating...' : 'Generate key'}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </>
                    ) : (
                        <>
                            <DialogHeader>
                                <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">Copy your API key now</DialogTitle>
                                <DialogDescription className="text-[#71717a]">
                                    This key will not be shown again.
                                </DialogDescription>
                            </DialogHeader>

                            <div className="mt-4 space-y-4">
                                <div className="rounded-2xl border border-[#7c3aed]/30 bg-[#18181b] p-4">
                                    <div className="flex items-start justify-between gap-3">
                                        <div>
                                            <p className="text-sm font-medium text-white">{createdKey.name}</p>
                                            <p className="mt-1 text-xs text-[#71717a]">
                                                Project: {createdKey.project_name || 'Default project'} ({createdKey.project_slug || 'default'})
                                            </p>
                                        </div>
                                        <CopyButton value={createdKey.key} className="border border-[#27272a] bg-[#111111] text-white hover:bg-[#18181b]" />
                                    </div>
                                    <div className="mt-4 overflow-x-auto rounded-xl border border-[#27272a] bg-[#111111] px-4 py-3">
                                        <code className="font-mono text-sm text-[#c4b5fd]">{createdKey.key}</code>
                                    </div>
                                </div>

                                <div className="flex items-start gap-3 rounded-2xl border border-amber-500/25 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
                                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                                    <p>This key will not be shown again. Copy it now and store it somewhere secure.</p>
                                </div>
                            </div>

                            <DialogFooter className="mt-6">
                                <Button
                                    type="button"
                                    onClick={closeCreateDialog}
                                    className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                                >
                                    Done
                                </Button>
                            </DialogFooter>
                        </>
                    )}
                </DialogContent>
            </Dialog>

            <ConfirmDialog
                open={!!revokeTarget}
                onOpenChange={() => setRevokeTarget(null)}
                title="Revoke API key"
                description={`Revoke ${revokeTarget?.name || 'this API key'}? It will stop authenticating requests immediately.`}
                confirmLabel="Revoke"
                onConfirm={() => revokeMutation.mutate(revokeTarget.id)}
                isLoading={revokeMutation.isPending}
            />
        </div>
    );
}
