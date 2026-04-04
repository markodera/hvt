import { Fragment, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronUp, ExternalLink, Pencil, Plus, Webhook as WebhookIcon } from 'lucide-react';
import { toast } from 'sonner';

import { listProjects } from '@/api/organizations';
import { createWebhook, deleteWebhook, getWebhookDeliveries, listWebhooks, updateWebhook } from '@/api/webhooks';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { formatDate, formatRelativeTime, getErrorMessage, truncate } from '@/lib/utils';

const webhookEventOptions = [
    { value: 'user.created', label: 'User created' },
    { value: 'user.updated', label: 'User updated' },
    { value: 'user.deleted', label: 'User deleted' },
    { value: 'user.login', label: 'User login' },
    { value: 'api_key.created', label: 'API key created' },
    { value: 'api_key.revoked', label: 'API key revoked' },
];

function TableCard({ children }) {
    return <section className="overflow-hidden rounded-2xl border border-[#27272a] bg-[#18181b]">{children}</section>;
}

function EmptyState({ message, action }) {
    return (
        <div className="flex min-h-[240px] flex-col items-center justify-center gap-3 px-6 py-10 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[#27272a] bg-[#111111] text-[#71717a]">
                <WebhookIcon className="h-6 w-6" />
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

function WebhookDeliveries({ webhookId }) {
    const { data, isLoading } = useQuery({
        queryKey: ['webhookDeliveries', webhookId],
        queryFn: () => getWebhookDeliveries(webhookId, { page_size: 3 }),
    });

    const deliveries = data?.results ?? [];

    if (isLoading) {
        return (
            <div className="space-y-2 px-4 py-4">
                {Array.from({ length: 3 }).map((_, index) => (
                    <div key={index} className="h-10 animate-pulse rounded-lg bg-[#1c1c1f]" />
                ))}
            </div>
        );
    }

    if (deliveries.length === 0) {
        return (
            <div className="px-4 py-5 text-sm text-[#71717a]">
                No deliveries yet. A delivery log appears after the endpoint is triggered.
            </div>
        );
    }

    return (
        <div className="space-y-2 px-4 py-4">
            {deliveries.map((delivery) => (
                <div
                    key={delivery.id}
                    className="flex flex-col gap-2 rounded-xl border border-[#27272a] bg-[#111111] px-4 py-3 text-sm md:flex-row md:items-center md:justify-between"
                >
                    <div>
                        <p className="font-medium text-white">{delivery.event_type}</p>
                        <p className="mt-1 font-mono text-xs text-[#71717a]">{formatDate(delivery.created_at)}</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="rounded-full border border-[#27272a] bg-[#18181b] px-2 py-1 text-[#a1a1aa]">
                            {delivery.response_status_code || 'n/a'}
                        </span>
                        <span className="rounded-full border border-[#27272a] bg-[#18181b] px-2 py-1 text-[#a1a1aa]">
                            {delivery.attempt_count}/{delivery.max_attempts} attempts
                        </span>
                        <span
                            className={`rounded-full px-2 py-1 ${
                                delivery.status === 'success'
                                    ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                    : delivery.status === 'failed'
                                      ? 'border border-rose-500/30 bg-rose-500/10 text-rose-300'
                                      : 'border border-[#27272a] bg-[#18181b] text-[#a1a1aa]'
                            }`}
                        >
                            {delivery.status}
                        </span>
                    </div>
                </div>
            ))}
        </div>
    );
}

function buildDraft(projectId = '') {
    return {
        project_id: projectId,
        url: '',
        events: [],
        description: '',
        is_active: true,
    };
}

export default function WebhooksPage() {
    const queryClient = useQueryClient();
    const [page, setPage] = useState(1);
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingWebhook, setEditingWebhook] = useState(null);
    const [deleteTarget, setDeleteTarget] = useState(null);
    const [expandedId, setExpandedId] = useState(null);

    const projectsQuery = useQuery({
        queryKey: ['projects', { page_size: 100 }],
        queryFn: () => listProjects({ page_size: 100 }),
    });

    const projects = projectsQuery.data?.results ?? [];
    const defaultProjectId = useMemo(
        () => projects.find((project) => project.is_default)?.id || projects[0]?.id || '',
        [projects]
    );
    const [draft, setDraft] = useState(() => buildDraft(''));

    const { data, isLoading, isError } = useQuery({
        queryKey: ['webhooks', { page }],
        queryFn: () => listWebhooks({ page, page_size: 10 }),
    });

    const createMutation = useMutation({
        mutationFn: createWebhook,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['webhooks'] });
            setDialogOpen(false);
            setEditingWebhook(null);
            setDraft(buildDraft(defaultProjectId));
            toast.success('Webhook endpoint added');
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    const updateMutation = useMutation({
        mutationFn: ({ id, payload }) => updateWebhook(id, payload),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['webhooks'] });
            setDialogOpen(false);
            setEditingWebhook(null);
            setDraft(buildDraft(defaultProjectId));
            toast.success('Webhook updated');
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    const deleteMutation = useMutation({
        mutationFn: deleteWebhook,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['webhooks'] });
            setDeleteTarget(null);
            toast.success('Webhook removed');
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    const webhooks = data?.results ?? [];
    const selectedEvents = draft.events || [];

    function openCreateDialog() {
        setEditingWebhook(null);
        setDraft(buildDraft(defaultProjectId));
        setDialogOpen(true);
    }

    function openEditDialog(webhook) {
        setEditingWebhook(webhook);
        setDraft({
            project_id: webhook.project || defaultProjectId,
            url: webhook.url,
            events: webhook.events || [],
            description: webhook.description || '',
            is_active: webhook.is_active,
        });
        setDialogOpen(true);
    }

    function closeDialog() {
        setDialogOpen(false);
        window.setTimeout(() => {
            setEditingWebhook(null);
            setDraft(buildDraft(defaultProjectId));
        }, 120);
    }

    function toggleEvent(eventType) {
        setDraft((current) => {
            const exists = current.events.includes(eventType);
            return {
                ...current,
                events: exists
                    ? current.events.filter((item) => item !== eventType)
                    : [...current.events, eventType],
            };
        });
    }

    function submitWebhook(event) {
        event.preventDefault();

        if (!draft.project_id) {
            toast.error('Select a project for this webhook.');
            return;
        }

        if (!draft.url.trim()) {
            toast.error('Enter an endpoint URL.');
            return;
        }

        if (!draft.events.length) {
            toast.error('Select at least one event.');
            return;
        }

        const payload = {
            project_id: draft.project_id,
            url: draft.url.trim(),
            events: draft.events,
            description: draft.description.trim(),
            is_active: draft.is_active,
        };

        if (editingWebhook) {
            updateMutation.mutate({ id: editingWebhook.id, payload });
            return;
        }

        createMutation.mutate(payload);
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-end">
                <button
                    type="button"
                    onClick={openCreateDialog}
                    className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                >
                    <Plus className="h-4 w-4" />
                    Add endpoint
                </button>
            </div>

            <TableCard>
                <div className="overflow-x-auto">
                    <table className="min-w-[980px] w-full">
                        <thead>
                            <tr className="border-b border-[#27272a] text-left text-[11px] uppercase tracking-[0.18em] text-[#71717a]">
                                <th className="w-12 px-4 py-3 font-medium" />
                                <th className="px-4 py-3 font-medium">Endpoint URL</th>
                                <th className="px-4 py-3 font-medium">Project</th>
                                <th className="px-4 py-3 font-medium">Events subscribed</th>
                                <th className="px-4 py-3 font-medium">Last triggered</th>
                                <th className="px-4 py-3 font-medium">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {isLoading ? Array.from({ length: 5 }).map((_, index) => <SkeletonRow key={index} />) : null}
                            {!isLoading && isError ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState message="Webhook endpoints could not be loaded right now." />
                                    </td>
                                </tr>
                            ) : null}
                            {!isLoading && !isError && webhooks.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-12">
                                        <EmptyState
                                            message="No webhook endpoints yet. Add an endpoint to receive delivery events from HVT."
                                            action={
                                                <button
                                                    type="button"
                                                    onClick={openCreateDialog}
                                                    className="inline-flex h-10 items-center justify-center rounded-md border border-[#7c3aed]/40 px-4 text-sm font-semibold text-[#a78bfa] transition-colors hover:bg-[#111111]"
                                                >
                                                    Add endpoint
                                                </button>
                                            }
                                        />
                                    </td>
                                </tr>
                            ) : null}
                            {!isLoading &&
                                !isError &&
                                webhooks.map((webhook) => {
                                    const expanded = expandedId === webhook.id;
                                    return (
                                        <Fragment key={webhook.id}>
                                            <tr className="border-b border-[#27272a] last:border-b-0">
                                                <td className="px-4 py-3">
                                                    <button
                                                        type="button"
                                                        onClick={() => setExpandedId(expanded ? null : webhook.id)}
                                                        className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-[#27272a] bg-[#111111] text-[#a1a1aa] transition-colors hover:bg-[#18181b] hover:text-white"
                                                    >
                                                        {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                                                    </button>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <a
                                                        href={webhook.url}
                                                        target="_blank"
                                                        rel="noreferrer"
                                                        className="inline-flex items-center gap-1 text-sm font-medium text-white transition-colors hover:text-[#a78bfa]"
                                                    >
                                                        {truncate(webhook.url, 52)}
                                                        <ExternalLink className="h-3.5 w-3.5" />
                                                    </a>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="text-sm text-white">{webhook.project_name}</div>
                                                    <div className="mt-1 inline-flex rounded-full border border-[#7c3aed]/30 bg-[#7c3aed]/10 px-2 py-1 font-mono text-[11px] text-[#c4b5fd]">
                                                        {webhook.project_slug}
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3 text-sm text-[#a1a1aa]">{webhook.events?.length || 0} events</td>
                                                <td className="px-4 py-3 font-mono text-xs text-[#71717a]">
                                                    {webhook.last_triggered_at ? formatRelativeTime(webhook.last_triggered_at) : 'Never'}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        <span className={`h-2 w-2 rounded-full ${webhook.is_active ? 'bg-emerald-400' : 'bg-[#52525b]'}`} />
                                                        <span className="text-sm text-[#a1a1aa]">{webhook.is_active ? 'Active' : 'Inactive'}</span>
                                                    </div>
                                                </td>
                                            </tr>
                                            {expanded ? (
                                                <tr className="border-b border-[#27272a] last:border-b-0">
                                                    <td colSpan={6} className="bg-[#161618] px-0 py-0">
                                                        <div className="flex flex-col gap-3 border-b border-[#27272a] px-4 py-3 md:flex-row md:items-center md:justify-between">
                                                            <div>
                                                                <p className="text-sm font-medium text-white">Recent deliveries</p>
                                                                <p className="text-xs text-[#71717a]">
                                                                    Status code and timestamp are shown inline. Response duration is not exposed by the current API.
                                                                </p>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <button
                                                                    type="button"
                                                                    onClick={() => openEditDialog(webhook)}
                                                                    className="inline-flex h-9 items-center justify-center rounded-md border border-[#27272a] bg-[#111111] px-3 text-sm font-medium text-white transition-colors hover:bg-[#18181b]"
                                                                >
                                                                    <Pencil className="mr-2 h-4 w-4" />
                                                                    Edit
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    onClick={() => setDeleteTarget(webhook)}
                                                                    className="inline-flex h-9 items-center justify-center rounded-md border border-rose-500/30 bg-rose-500/10 px-3 text-sm font-medium text-rose-300 transition-colors hover:bg-rose-500/15"
                                                                >
                                                                    Delete
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <WebhookDeliveries webhookId={webhook.id} />
                                                    </td>
                                                </tr>
                                            ) : null}
                                        </Fragment>
                                    );
                                })}
                        </tbody>
                    </table>
                </div>

                {data?.count ? <Pagination count={data.count} page={page} onPageChange={setPage} /> : null}
            </TableCard>

            <Dialog open={dialogOpen} onOpenChange={(open) => (open ? setDialogOpen(true) : closeDialog())}>
                <DialogContent className="max-w-2xl border-[#27272a] bg-[#111111] text-white">
                    <DialogHeader>
                        <DialogTitle className="text-xl font-bold tracking-[-0.03em] text-white">
                            {editingWebhook ? 'Edit webhook endpoint' : 'Add webhook endpoint'}
                        </DialogTitle>
                        <DialogDescription className="text-[#71717a]">
                            Choose the project, subscribe events, and manage recent deliveries inline.
                        </DialogDescription>
                    </DialogHeader>

                    <form onSubmit={submitWebhook} className="mt-4 space-y-5">
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
                            <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Endpoint URL</Label>
                            <Input
                                value={draft.url}
                                onChange={(event) => setDraft((current) => ({ ...current, url: event.target.value }))}
                                placeholder="https://example.com/webhooks/hvt"
                                className="h-10 border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a] focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                            />
                        </div>

                        <div className="space-y-2">
                            <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Description</Label>
                            <Input
                                value={draft.description}
                                onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))}
                                placeholder="Slack notifications"
                                className="h-10 border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a] focus:border-[#7c3aed] focus:ring-[#7c3aed]/25"
                            />
                        </div>

                        <div className="space-y-3">
                            <Label className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]">Events subscribed</Label>
                            <div className="grid gap-2 sm:grid-cols-2">
                                {webhookEventOptions.map((eventType) => {
                                    const selected = selectedEvents.includes(eventType.value);
                                    return (
                                        <button
                                            key={eventType.value}
                                            type="button"
                                            onClick={() => toggleEvent(eventType.value)}
                                            className={`rounded-xl border px-3 py-3 text-left transition-colors ${
                                                selected
                                                    ? 'border-[#7c3aed]/50 bg-[#7c3aed]/10 text-white'
                                                    : 'border-[#27272a] bg-[#18181b] text-[#a1a1aa] hover:border-[#7c3aed]/30'
                                            }`}
                                        >
                                            <p className="text-sm font-medium">{eventType.label}</p>
                                            <p className="mt-1 font-mono text-[11px] text-[#71717a]">{eventType.value}</p>
                                        </button>
                                    );
                                })}
                            </div>
                        </div>

                        <label className="flex items-center gap-3 rounded-xl border border-[#27272a] bg-[#18181b] px-4 py-3 text-sm text-[#a1a1aa]">
                            <input
                                type="checkbox"
                                checked={draft.is_active}
                                onChange={(event) => setDraft((current) => ({ ...current, is_active: event.target.checked }))}
                                className="h-4 w-4 rounded border-[#3f3f46] bg-[#111111] text-[#7c3aed] focus:ring-[#7c3aed]/40"
                            />
                            Endpoint is active
                        </label>

                        <DialogFooter>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={closeDialog}
                                className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                            >
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={createMutation.isPending || updateMutation.isPending}
                                className="bg-[#7c3aed] text-white hover:bg-[#6d28d9]"
                            >
                                {createMutation.isPending || updateMutation.isPending
                                    ? 'Saving...'
                                    : editingWebhook
                                      ? 'Save changes'
                                      : 'Add endpoint'}
                            </Button>
                        </DialogFooter>
                    </form>
                </DialogContent>
            </Dialog>

            <ConfirmDialog
                open={!!deleteTarget}
                onOpenChange={() => setDeleteTarget(null)}
                title="Delete webhook"
                description={`Delete ${deleteTarget?.url || 'this webhook'}? Delivery history for this endpoint will be removed.`}
                confirmLabel="Delete"
                onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
                isLoading={deleteMutation.isPending}
            />
        </div>
    );
}
