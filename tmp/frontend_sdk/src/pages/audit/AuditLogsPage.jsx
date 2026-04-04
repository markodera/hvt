import { Fragment, useMemo } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { CalendarRange, Info, ScrollText } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import { listAuditLogs } from '@/api/auditLogs';
import { useAuth } from '@/hooks/useAuth';
import { formatDate } from '@/lib/utils';

const actionOptions = [
    { value: '', label: 'All actions' },
    { value: 'user.login', label: 'User login' },
    { value: 'user.logout', label: 'User logout' },
    { value: 'user.register', label: 'User register' },
    { value: 'api_key.created', label: 'API key created' },
    { value: 'api_key.revoked', label: 'API key revoked' },
    { value: 'org.updated', label: 'Organisation updated' },
    { value: 'project.created', label: 'Project created' },
    { value: 'project.updated', label: 'Project updated' },
    { value: 'project.deleted', label: 'Project deleted' },
    { value: 'org.invitation.created', label: 'Invitation created' },
];

function extractCursor(nextUrl) {
    if (!nextUrl) {
        return null;
    }

    try {
        return new URL(nextUrl).searchParams.get('cursor');
    } catch (error) {
        return null;
    }
}

function EmptyState({ message }) {
    return (
        <div className="flex min-h-[280px] flex-col items-center justify-center gap-3 px-6 py-10 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border border-[#27272a] bg-[#111111] text-[#71717a]">
                <ScrollText className="h-6 w-6" />
            </div>
            <p className="max-w-md text-sm leading-6 text-[#71717a]">{message}</p>
        </div>
    );
}

function actionBadgeClass(eventType) {
    if (eventType.includes('created')) {
        return 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    }
    if (eventType.includes('updated') || eventType.includes('changed')) {
        return 'border border-sky-500/30 bg-sky-500/10 text-sky-300';
    }
    if (eventType.includes('deleted') || eventType.includes('revoked')) {
        return 'border border-rose-500/30 bg-rose-500/10 text-rose-300';
    }
    if (eventType.includes('login')) {
        return 'border border-violet-500/30 bg-violet-500/10 text-violet-300';
    }
    if (eventType.includes('logout')) {
        return 'border border-[#27272a] bg-[#18181b] text-[#a1a1aa]';
    }
    return 'border border-[#27272a] bg-[#18181b] text-[#a1a1aa]';
}

function withinDateRange(value, from, to) {
    if (!value) {
        return false;
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return false;
    }

    if (from) {
        const fromDate = new Date(`${from}T00:00:00`);
        if (date < fromDate) {
            return false;
        }
    }

    if (to) {
        const toDate = new Date(`${to}T23:59:59`);
        if (date > toDate) {
            return false;
        }
    }

    return true;
}

export default function AuditLogsPage() {
    const { user } = useAuth();
    const [searchParams, setSearchParams] = useSearchParams();
    const eventType = searchParams.get('event_type') || '';
    const actorSearch = searchParams.get('actor_search') || '';
    const dateFrom = searchParams.get('date_from') || '';
    const dateTo = searchParams.get('date_to') || '';
    const projectScoped = Boolean(user?.is_project_scoped && user?.project_slug);

    const query = useInfiniteQuery({
        queryKey: ['auditLogs', { eventType }],
        queryFn: ({ pageParam }) =>
            listAuditLogs({
                page_size: 20,
                ...(eventType ? { event_type: eventType } : {}),
                ...(pageParam ? { cursor: pageParam } : {}),
            }),
        initialPageParam: null,
        getNextPageParam: (lastPage) => extractCursor(lastPage?.next),
    });

    const logs = useMemo(() => {
        const allLogs = query.data?.pages.flatMap((page) => page.results ?? []) ?? [];
        return allLogs.filter((log) => {
            const matchesActor = actorSearch
                ? `${log.actor_email || ''} ${log.actor_api_key_name || ''}`
                      .toLowerCase()
                      .includes(actorSearch.toLowerCase())
                : true;
            const matchesDate =
                !dateFrom && !dateTo ? true : withinDateRange(log.created_at, dateFrom, dateTo);

            return matchesActor && matchesDate;
        });
    }, [actorSearch, dateFrom, dateTo, query.data?.pages]);

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

    return (
        <div className="space-y-6">
            {projectScoped ? (
                <section className="flex items-center gap-3 rounded-2xl border border-[#27272a] bg-[#18181b] px-4 py-3 text-sm text-[#a1a1aa]">
                    <Info className="h-4 w-4 text-[#a78bfa]" />
                    <p>
                        Showing results scoped to project: <span className="font-mono text-[#c4b5fd]">{user.project_slug}</span>
                    </p>
                </section>
            ) : null}

            <section className="rounded-2xl border border-[#27272a] bg-[#18181b] p-4">
                <div className="grid gap-3 lg:grid-cols-[minmax(0,240px)_minmax(0,240px)_minmax(0,1fr)]">
                    <select
                        value={eventType}
                        onChange={(event) => updateParams({ event_type: event.target.value || null })}
                        className="h-10 rounded-md border border-[#27272a] bg-[#111111] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                    >
                        {actionOptions.map((option) => (
                            <option key={option.value || 'all'} value={option.value}>
                                {option.label}
                            </option>
                        ))}
                    </select>

                    <div className="flex items-center gap-2 rounded-md border border-[#27272a] bg-[#111111] px-3">
                        <CalendarRange className="h-4 w-4 text-[#71717a]" />
                        <input
                            type="date"
                            value={dateFrom}
                            onChange={(event) => updateParams({ date_from: event.target.value || null })}
                            className="h-10 w-full bg-transparent text-sm text-white outline-none"
                        />
                    </div>

                    <div className="grid gap-3 md:grid-cols-2">
                        <input
                            type="text"
                            value={actorSearch}
                            onChange={(event) => updateParams({ actor_search: event.target.value || null })}
                            placeholder="Filter visible actors"
                            className="h-10 rounded-md border border-[#27272a] bg-[#111111] px-3 text-sm text-white outline-none transition-colors placeholder:text-[#71717a] focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                        />
                        <input
                            type="date"
                            value={dateTo}
                            onChange={(event) => updateParams({ date_to: event.target.value || null })}
                            className="h-10 rounded-md border border-[#27272a] bg-[#111111] px-3 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25"
                        />
                    </div>
                </div>
            </section>

            <section className="overflow-hidden rounded-2xl border border-[#27272a] bg-[#18181b]">
                {query.isLoading ? (
                    <div className="space-y-3 px-4 py-4">
                        {Array.from({ length: 12 }).map((_, index) => (
                            <div key={index} className="h-10 animate-pulse rounded bg-[#1c1c1f]" />
                        ))}
                    </div>
                ) : query.isError ? (
                    <EmptyState message="Audit logs could not be loaded right now." />
                ) : logs.length === 0 ? (
                    <EmptyState message="No audit events match the current filters. Events are recorded when users sign in, keys are issued, invitations are sent, and projects change." />
                ) : (
                    <>
                        <div className="overflow-x-auto">
                            <table className="min-w-[980px] w-full">
                                <thead>
                                    <tr className="border-b border-[#27272a] text-left text-[11px] uppercase tracking-[0.18em] text-[#71717a]">
                                        <th className="px-4 py-3 font-medium">Timestamp</th>
                                        <th className="px-4 py-3 font-medium">Actor</th>
                                        <th className="px-4 py-3 font-medium">Action</th>
                                        <th className="px-4 py-3 font-medium">Resource</th>
                                        <th className="px-4 py-3 font-medium">IP</th>
                                        <th className="px-4 py-3 font-medium">Project</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.map((log) => (
                                        <Fragment key={log.id}>
                                            <tr className="border-b border-[#27272a] last:border-b-0">
                                                <td className="px-4 py-3 font-mono text-xs text-[#71717a]">
                                                    {formatDate(log.created_at)}
                                                </td>
                                                <td className="px-4 py-3 text-sm text-[#a1a1aa]">
                                                    {log.actor_email || log.actor_api_key_name || 'System'}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${actionBadgeClass(log.event_type)}`}>
                                                        {log.event_type}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-sm text-[#a1a1aa]">
                                                    {log.target_type || 'system'}
                                                </td>
                                                <td className="px-4 py-3 font-mono text-xs text-[#71717a]">
                                                    {log.ip_address || '-'}
                                                </td>
                                                <td className="px-4 py-3 font-mono text-xs text-[#71717a]">
                                                    {log.project
                                                        ? projectScoped
                                                            ? user.project_slug
                                                            : String(log.project).slice(0, 8)
                                                        : 'Org'}
                                                </td>
                                            </tr>
                                        </Fragment>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {query.hasNextPage ? (
                            <div className="border-t border-[#27272a] px-4 py-4">
                                <button
                                    type="button"
                                    onClick={() => query.fetchNextPage()}
                                    disabled={query.isFetchingNextPage}
                                    className="inline-flex h-10 items-center justify-center rounded-md border border-[#27272a] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#111111] disabled:cursor-not-allowed disabled:opacity-50"
                                >
                                    {query.isFetchingNextPage ? 'Loading more...' : 'Load more'}
                                </button>
                            </div>
                        ) : null}
                    </>
                )}
            </section>
        </div>
    );
}
