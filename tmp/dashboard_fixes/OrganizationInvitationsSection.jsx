import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { MailPlus, RefreshCw, ShieldPlus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import {
    createOrganizationInvitation,
    listOrganizationInvitations,
    resendOrganizationInvitation,
    revokeOrganizationInvitation,
} from '@/api/organizations';
import { organizationInvitationCreateSchema } from '@/lib/schemas';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { CopyButton } from '@/components/CopyButton';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { LoadingSpinner } from '@/components/LoadingSpinner';
import { formatDate, getErrorMessage } from '@/lib/utils';

const selectClassName =
    'flex h-10 w-full rounded-lg border border-[#27272a] bg-[#18181b] px-3 py-2 text-sm text-white outline-none transition-colors focus:border-[#7c3aed] focus:ring-2 focus:ring-[#7c3aed]/25';

function badgeVariantForStatus(status) {
    if (status === 'accepted') return 'success';
    if (status === 'revoked' || status === 'expired') return 'warning';
    return 'secondary';
}

export function OrganizationInvitationsSection() {
    const queryClient = useQueryClient();
    const [revokeTarget, setRevokeTarget] = useState(null);

    const { data, isLoading, isError } = useQuery({
        queryKey: ['organizationInvitations'],
        queryFn: () => listOrganizationInvitations({ page_size: 50 }),
    });

    const invitations = data?.results ?? data ?? [];

    const form = useForm({
        resolver: zodResolver(organizationInvitationCreateSchema),
        defaultValues: {
            email: '',
            role: 'member',
        },
    });

    const invalidateInvitations = () => {
        queryClient.invalidateQueries({ queryKey: ['organizationInvitations'] });
    };

    const createInvitationMutation = useMutation({
        mutationFn: createOrganizationInvitation,
        onSuccess: () => {
            invalidateInvitations();
            form.reset({ email: '', role: 'member' });
            toast.success('Invitation sent');
        },
        onError: (error) => toast.error(getErrorMessage(error)),
    });

    const resendInvitationMutation = useMutation({
        mutationFn: resendOrganizationInvitation,
        onSuccess: () => {
            invalidateInvitations();
            toast.success('Invitation email resent');
        },
        onError: (error) => toast.error(getErrorMessage(error)),
    });

    const revokeInvitationMutation = useMutation({
        mutationFn: revokeOrganizationInvitation,
        onSuccess: () => {
            invalidateInvitations();
            setRevokeTarget(null);
            toast.success('Invitation revoked');
        },
        onError: (error) => toast.error(getErrorMessage(error)),
    });

    return (
        <>
            <div className="space-y-6 rounded-xl border border-[#27272a] bg-[#111111] p-6">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                        <div className="flex items-center gap-2">
                            <ShieldPlus className="h-5 w-5 text-[#a78bfa]" />
                            <h2 className="text-lg font-bold text-white">Invitations</h2>
                        </div>
                        <p className="mt-1 text-sm text-[#a1a1aa]">
                            Invite admins or members into this organization. Invite links stay outside project scope on purpose.
                        </p>
                    </div>
                    <Badge variant="secondary">{invitations.length} total</Badge>
                </div>

                <form
                    onSubmit={form.handleSubmit((values) => createInvitationMutation.mutate(values))}
                    className="grid gap-4 rounded-xl border border-[#27272a] bg-[#111111] p-4 md:grid-cols-[minmax(0,1fr)_180px_auto]"
                >
                    <div className="space-y-2">
                        <Label
                            htmlFor="invite-email"
                            className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]"
                        >
                            Invite by email
                        </Label>
                        <Input
                            id="invite-email"
                            type="email"
                            placeholder="teammate@example.com"
                            className="border-[#27272a] bg-[#18181b] text-white placeholder:text-[#71717a]"
                            {...form.register('email')}
                        />
                        {form.formState.errors.email && (
                            <p className="text-xs text-danger">{form.formState.errors.email.message}</p>
                        )}
                    </div>

                    <div className="space-y-2">
                        <Label
                            htmlFor="invite-role"
                            className="text-xs font-semibold uppercase tracking-[0.18em] text-[#71717a]"
                        >
                            Role
                        </Label>
                        <select id="invite-role" className={selectClassName} {...form.register('role')}>
                            <option value="member">Member</option>
                            <option value="admin">Admin</option>
                        </select>
                        {form.formState.errors.role && (
                            <p className="text-xs text-danger">{form.formState.errors.role.message}</p>
                        )}
                    </div>

                    <div className="flex items-end">
                        <Button
                            type="submit"
                            className="w-full bg-[#7c3aed] text-white hover:bg-[#6d28d9] md:w-auto"
                            disabled={createInvitationMutation.isPending}
                        >
                            <MailPlus className="mr-2 h-4 w-4" />
                            {createInvitationMutation.isPending ? 'Sending...' : 'Send invite'}
                        </Button>
                    </div>
                </form>

                {isLoading && <LoadingSpinner size="sm" />}
                {isError && (
                    <div className="rounded-xl border border-dashed border-[#27272a] bg-[#18181b] p-4 text-sm text-[#71717a]">
                        Failed to load invitations.
                    </div>
                )}
                {!isLoading && !isError && invitations.length === 0 && (
                    <div className="rounded-xl border border-dashed border-[#27272a] bg-[#18181b] p-4 text-sm text-[#71717a]">
                        No invitations yet.
                    </div>
                )}

                <div className="space-y-3">
                    {invitations.map((invitation) => {
                        const isPending = invitation.status === 'pending';
                        return (
                            <div key={invitation.id} className="space-y-3 rounded-xl border border-[#27272a] bg-[#111111] p-4">
                                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                                    <div className="space-y-2">
                                        <div className="flex flex-wrap items-center gap-2">
                                            <p className="font-medium text-white">{invitation.email}</p>
                                            <Badge variant={badgeVariantForStatus(invitation.status)}>{invitation.status}</Badge>
                                            <Badge variant={invitation.role === 'admin' ? 'default' : 'secondary'}>
                                                {invitation.role}
                                            </Badge>
                                        </div>
                                        <p className="text-xs text-[#a1a1aa]">
                                            Expires {formatDate(invitation.expires_at)}
                                        </p>
                                        <p className="break-all font-mono text-xs text-[#71717a]">{invitation.accept_url}</p>
                                    </div>
                                    <div className="flex flex-wrap gap-2">
                                        <CopyButton
                                            value={invitation.accept_url}
                                            className="border border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                                        />
                                        {isPending && (
                                            <Button
                                                type="button"
                                                variant="outline"
                                                size="sm"
                                                onClick={() => resendInvitationMutation.mutate(invitation.id)}
                                                disabled={resendInvitationMutation.isPending}
                                                className="border-[#27272a] bg-transparent text-white hover:bg-[#18181b]"
                                            >
                                                <RefreshCw className="mr-2 h-4 w-4" />
                                                Resend
                                            </Button>
                                        )}
                                        {isPending && (
                                            <Button
                                                type="button"
                                                variant="destructive"
                                                size="sm"
                                                onClick={() => setRevokeTarget(invitation)}
                                                disabled={revokeInvitationMutation.isPending}
                                            >
                                                <Trash2 className="mr-2 h-4 w-4" />
                                                Revoke
                                            </Button>
                                        )}
                                    </div>
                                </div>
                                <div className="grid gap-2 text-xs text-[#a1a1aa] md:grid-cols-3">
                                    <p>Invited by {invitation.invited_by_email || 'Unknown'}</p>
                                    <p>Accepted by {invitation.accepted_by_email || 'Not yet accepted'}</p>
                                    <p>Created {formatDate(invitation.created_at)}</p>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            <ConfirmDialog
                open={!!revokeTarget}
                onOpenChange={() => setRevokeTarget(null)}
                title="Revoke invitation"
                description={`Revoke the invite for ${revokeTarget?.email || 'this user'}? The current token will stop working immediately.`}
                confirmLabel="Revoke invitation"
                onConfirm={() => revokeInvitationMutation.mutate(revokeTarget.id)}
                isLoading={revokeInvitationMutation.isPending}
            />
        </>
    );
}
