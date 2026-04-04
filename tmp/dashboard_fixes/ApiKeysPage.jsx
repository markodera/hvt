import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AlertTriangle, KeyRound, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { createApiKey, listApiKeys, revokeApiKey } from '@/api/apiKeys';
import { listProjects } from '@/api/organizations';
import { SCOPES } from '@/lib/constants';
import { createKeySchema } from '@/lib/schemas';
import { formatDate, formatRelativeTime, getErrorMessage } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { CopyButton } from '@/components/CopyButton';

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

function ScopeRow({ scope, selected, onToggle }) {
    const [hovered, setHovered] = useState(false);
    const showHelper = scope.value === 'auth:runtime' && (hovered || selected);

    return (
        <div
            className="group"
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
        >
            <button
                type="button"
                onClick={onToggle}
                className={`flex h-11 w-full items-center gap-3 border border-[#27272a] px-3 text-left transition-colors ${selected ? 'border-l-2 border-l-[#7c3aed] bg-[#18181b]' : 'bg-transparent hover:bg-[#18181b]'}`}
            >
                <input
                    type="checkbox"
                    checked={selected}
                    onChange={onToggle}
                    className="h-4 w-4 rounded border-[#3f3f46] bg-[#111111] accent-[#7c3aed]"
                />
                <span className={`flex-1 text-sm font-medium ${selected ? 'text-white' : 'text-[#a1a1aa]'}`}>
                    {scope.label}
                </span>
                <span className="font-mono text-xs text-[#71717a]">{scope.value}</span>
            </button>
            {scope.helper ? (
                <p
                    className={`pl-7 pt-2 text-[12px] text-[#71717a] transition-opacity ${showHelper ? 'opacity-100' : 'pointer-events-none opacity-0'}`}
                >
                    {scope.helper}
                </p>
            ) : null}
        </div>
    );
}

export function ApiKeysPage() {
    const queryClient = useQueryClient();
    const [searchParams, setSearchParams] = useSearchParams();
    const [createOpen, setCreateOpen] = useState(false);
    const [revealedKey, setRevealedKey] = useState('');
    const [revokeTarget, setRevokeTarget] = useState(null);

    const page = Number(searchParams.get('page') || 1);
    const projectFilter = searchParams.get('project') || '';

    const { data: projectsData } = useQuery({
        queryKey: ['projects'],
        queryFn: listProjects,
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
            expires_at: '',
        },
    });

    const selectedScopes = form.watch('scopes') || [];
    const selectedEnvironment = form.watch('environment');

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
        mutationFn: (values) =>
            createApiKey({
                ...values,
                expires_at: values.expires_at || null,
            }),
        onSuccess: (createdKey) => {
            queryClient.invalidateQueries({ queryKey: ['apiKeys'] });
            setCreateOpen(false);
            setRevealedKey(createdKey.key);
            form.reset({
                name: '',
                environment: 'test',
                project_id: projects.find((project) => project.is_default)?.id || projects[0]?.id || '',
                scopes: ['auth:runtime'],
                expires_at: '',
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

    function toggleScope(scopeValue) {
        const current = form.getValues('scopes') || [];
        if (current.includes(scopeValue)) {
            form.setValue(
                'scopes',
                current.filter((scope) => scope !== scopeValue),
                { shouldDirty: true, shouldValidate: true }
            );
            return;
        }

        form.setValue('scopes', [...current, scopeValue], {
            shouldDirty: true,
            shouldValidate: true,
        });
    }

    const keys = data?.results ?? [];

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                <div>
                    <h2 className="text-lg font-bold text-white">API Keys</h2>
                    <p className="mt-1 text-sm text-[#a1a1aa]">
                        Issue project-scoped keys for runtime auth and service integrations.
                    </p>
                </div>

                <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                    <select
                        value={projectFilter}
                        onChange={(event) => updateParams({ project: event.target.value, page: 1 })}
                        className="h-10 rounded-md border border-[#27272a] bg-[#111111] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                    >
                        <option value="">All projects</option>
                        {projects.map((project) => (
                            <option key={project.id} value={project.id}>
                                {project.name}
                            </option>
                        ))}
                    </select>

                    <button
                        type="button"
                        onClick={() => setCreateOpen(true)}
                        className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                    >
                        <Plus className="h-4 w-4" />
                        Issue new key
                    </button>
                </div>
            </div>

            <TableCard>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-[#27272a]">
                        <thead className="bg-[#111111]">
                            <tr>
                                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Key prefix
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Project
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Created
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Last used
                                </th>
                                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Status
                                </th>
                                <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Actions
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading && Array.from({ length: 5 }).map((_, index) => <SkeletonRow key={index} />)}
                            {!isLoading && isError ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-8 text-center text-sm text-[#71717a]">
                                        Failed to load API keys.
                                    </td>
                                </tr>
                            ) : null}
                            {!isLoading && !isError && keys.length === 0 ? (
                                <tr>
                                    <td colSpan={6}>
                                        <EmptyState
                                            message="No API keys issued yet. Generate your first project key to start authenticating runtime requests."
                                            action={
                                                <button
                                                    type="button"
                                                    onClick={() => setCreateOpen(true)}
                                                    className="inline-flex h-10 items-center justify-center rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
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
                <DialogContent className="max-h-[85vh] max-w-[560px] overflow-hidden border-[#27272a] bg-[#111111] p-0 text-white">
                    <DialogHeader className="border-b border-[#27272a] px-6 pb-4 pt-6">
                        <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">
                            Issue API key
                        </DialogTitle>
                        <DialogDescription className="text-[#71717a]">
                            Create a project-scoped key for runtime auth or server-to-server access.
                        </DialogDescription>
                    </DialogHeader>

                    <form
                        onSubmit={form.handleSubmit((values) => createMutation.mutate(values))}
                        className="flex max-h-[calc(85vh-116px)] flex-col"
                    >
                        <div className="flex-1 overflow-y-auto px-6 pb-6 pt-5 [scrollbar-color:#3f3f46_transparent] [scrollbar-width:thin] [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#3f3f46] [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar]:w-2">
                            <section className="space-y-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Project + Key Name
                                </p>
                                <div className="grid gap-4 md:grid-cols-2">
                                    <div className="space-y-2">
                                        <Label className="text-white">Project</Label>
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
                                            <p className="text-xs text-rose-300">
                                                {form.formState.errors.project_id.message}
                                            </p>
                                        ) : null}
                                    </div>

                                    <div className="space-y-2">
                                        <Label className="text-white">Key name</Label>
                                        <Input
                                            {...form.register('name')}
                                            placeholder="Storefront runtime"
                                            className="border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a]"
                                        />
                                        {form.formState.errors.name ? (
                                            <p className="text-xs text-rose-300">
                                                {form.formState.errors.name.message}
                                            </p>
                                        ) : null}
                                    </div>
                                </div>
                            </section>

                            <section className="mt-6 space-y-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Environment
                                </p>
                                <div className="flex flex-wrap gap-2">
                                    {['test', 'live'].map((environment) => {
                                        const active = selectedEnvironment === environment;
                                        return (
                                            <button
                                                key={environment}
                                                type="button"
                                                onClick={() => form.setValue('environment', environment, { shouldDirty: true })}
                                                className={`inline-flex h-10 items-center justify-center rounded-md px-4 text-sm font-medium transition-colors ${active ? 'bg-[#7c3aed] text-white hover:bg-[#6d28d9]' : 'border border-[#27272a] bg-transparent text-[#a1a1aa] hover:bg-[#18181b] hover:text-white'}`}
                                            >
                                                {environment === 'test' ? 'Test' : 'Live'}
                                            </button>
                                        );
                                    })}
                                </div>
                            </section>

                            <section className="mt-6 space-y-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                    Expiry
                                </p>
                                <div className="space-y-2">
                                    <Label className="text-white">Expiration date</Label>
                                    <Input
                                        type="date"
                                        {...form.register('expires_at')}
                                        className="border-[#27272a] bg-[#18181b] text-white"
                                    />
                                    <p className="text-xs text-[#71717a]">
                                        Optional. Leave blank to keep the key active until it is revoked.
                                    </p>
                                </div>
                            </section>

                            <section className="mt-6 space-y-4">
                                <div>
                                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">
                                        Scopes
                                    </p>
                                    <p className="mt-1 text-sm text-[#a1a1aa]">
                                        Only launch scopes are available here.
                                    </p>
                                </div>

                                <div className="space-y-2">
                                    {SCOPES.map((scope) => (
                                        <ScopeRow
                                            key={scope.value}
                                            scope={scope}
                                            selected={selectedScopes.includes(scope.value)}
                                            onToggle={() => toggleScope(scope.value)}
                                        />
                                    ))}
                                </div>
                                {form.formState.errors.scopes ? (
                                    <p className="text-xs text-rose-300">
                                        {form.formState.errors.scopes.message}
                                    </p>
                                ) : null}
                            </section>
                        </div>

                        <DialogFooter className="sticky bottom-0 mt-0 border-t border-[#27272a] bg-[#111111] px-6 py-4 sm:justify-end">
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

            <Dialog open={Boolean(revealedKey)} onOpenChange={(open) => !open && setRevealedKey('')}>
                <DialogContent className="max-w-xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-white">API key created</DialogTitle>
                        <DialogDescription className="text-[#a1a1aa]">
                            Copy this key now. It will not be shown again.
                        </DialogDescription>
                    </DialogHeader>

                    <div className="mt-4 rounded-xl border border-[#27272a] bg-[#18181b] p-4">
                        <div className="flex items-start gap-3 text-sm text-[#fbbf24]">
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                            <p>This key will not be shown again.</p>
                        </div>

                        <div className="mt-4 flex items-start gap-2 rounded-lg border border-[#27272a] bg-[#111111] p-3">
                            <code className="flex-1 break-all font-mono text-sm text-white">{revealedKey}</code>
                            <CopyButton
                                value={revealedKey}
                                className="border border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                            />
                        </div>
                    </div>
                </DialogContent>
            </Dialog>

            <ConfirmDialog
                open={Boolean(revokeTarget)}
                onOpenChange={(open) => !open && setRevokeTarget(null)}
                title="Revoke API key"
                description={`Revoke ${revokeTarget?.name || 'this API key'}? Existing clients using it will stop authenticating immediately.`}
                confirmLabel="Revoke key"
                onConfirm={() => revokeMutation.mutate(revokeTarget.id)}
                isLoading={revokeMutation.isPending}
            />
        </div>
    );
}

export default ApiKeysPage;
