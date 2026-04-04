import { useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { AlertTriangle, Building2, Mail, ShieldCheck, Users } from 'lucide-react';
import { toast } from 'sonner';

import { acceptOrganizationInvitation, lookupOrganizationInvitation } from '@/api/organizations';
import {
    AuthCard,
    AuthPageShell,
    AUTH_GHOST_BUTTON_CLASS,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { useAuth } from '@/hooks/useAuth';
import {
    buildInvitationAuthPath,
    clearPendingInvitationToken,
    setPendingInvitationToken,
} from '@/lib/invitations';
import { formatDate, getErrorMessage } from '@/lib/utils';

function roleBadgeClass(role) {
    if (role === 'owner') return 'border-[#4c1d95] bg-[#2e1065] text-[#ddd6fe]';
    if (role === 'admin') return 'border-[#6d28d9] bg-[#2b124c] text-[#c4b5fd]';
    return 'border-[#3f3f46] bg-[#18181b] text-[#d4d4d8]';
}

function statusCopy(status) {
    if (status === 'accepted') {
        return 'This invitation has already been accepted.';
    }
    if (status === 'revoked') {
        return 'This invitation has been revoked.';
    }
    if (status === 'expired') {
        return 'This invitation has expired.';
    }
    return '';
}

export function InvitationAcceptPage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const { user, isAuthenticated, isLoading: authLoading, refreshSession } = useAuth();
    const token = (searchParams.get('token') || '').trim();

    useEffect(() => {
        document.title = 'Accept invitation | HVT';
    }, []);

    useEffect(() => {
        if (token) {
            setPendingInvitationToken(token);
        }
    }, [token]);

    const invitationQuery = useQuery({
        queryKey: ['organization-invitation-lookup', token],
        queryFn: () => lookupOrganizationInvitation(token),
        enabled: Boolean(token),
        retry: false,
    });

    const acceptMutation = useMutation({
        mutationFn: () => acceptOrganizationInvitation(token),
        onSuccess: async () => {
            await refreshSession();
            clearPendingInvitationToken();
            toast.success(`You've joined ${invitation.organization_name} as ${invitation.role}.`);
            navigate('/dashboard', { replace: true });
        },
        onError: (error) => {
            toast.error(getErrorMessage(error));
        },
    });

    if (!token) {
        return (
            <AuthPageShell>
                <AuthCard>
                    <div className="space-y-6 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#78350f] bg-[#1f1708] text-[#fbbf24]">
                            <AlertTriangle className="h-7 w-7" />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Invitation not found</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                No invitation token was provided in the URL.
                            </p>
                        </div>
                        <Link to="/login" className={AUTH_PRIMARY_BUTTON_CLASS}>
                            Back to sign in
                        </Link>
                    </div>
                </AuthCard>
            </AuthPageShell>
        );
    }

    if (authLoading || invitationQuery.isLoading) {
        return (
            <AuthPageShell>
                <AuthCard>
                    <div className="space-y-6 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a78bfa]">
                            <Users className="h-7 w-7" />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Loading invitation</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                Fetching the organization invite details now.
                            </p>
                        </div>
                    </div>
                </AuthCard>
            </AuthPageShell>
        );
    }

    if (invitationQuery.isError || !invitationQuery.data) {
        return (
            <AuthPageShell>
                <AuthCard>
                    <div className="space-y-6 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#78350f] bg-[#1f1708] text-[#fbbf24]">
                            <AlertTriangle className="h-7 w-7" />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Invitation unavailable</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">{getErrorMessage(invitationQuery.error)}</p>
                        </div>
                        <Link to="/login" className={AUTH_PRIMARY_BUTTON_CLASS}>
                            Back to sign in
                        </Link>
                    </div>
                </AuthCard>
            </AuthPageShell>
        );
    }

    const invitation = invitationQuery.data;
    const loginPath = buildInvitationAuthPath('/login', token);
    const signupPath = buildInvitationAuthPath('/signup', token);
    const signedInEmail = user?.email?.toLowerCase() || '';
    const invitationEmail = invitation.email?.toLowerCase() || '';
    const emailMatches = signedInEmail && invitationEmail && signedInEmail === invitationEmail;
    const canAccept = isAuthenticated && !user?.organization && emailMatches && invitation.status === 'pending';
    const statusMessage = statusCopy(invitation.status);

    return (
        <AuthPageShell>
            <AuthCard>
                <div className="space-y-6">
                    <div className="space-y-4 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a78bfa]">
                            <Users className="h-7 w-7" />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">
                                Join {invitation.organization_name}
                            </h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                This invitation adds you to the organization control plane.
                            </p>
                        </div>
                    </div>

                    <div className="rounded-2xl border border-[#27272a] bg-[#18181b] p-5">
                        <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] ${roleBadgeClass(invitation.role)}`}>
                                {invitation.role}
                            </span>
                            <span className="rounded-full border border-[#27272a] bg-[#111111] px-3 py-1 text-xs font-medium uppercase tracking-[0.14em] text-[#a1a1aa]">
                                {invitation.status}
                            </span>
                        </div>

                        <div className="mt-4 space-y-3 text-sm text-[#a1a1aa]">
                            <div className="flex items-center gap-3">
                                <Building2 className="h-4 w-4 text-[#a78bfa]" />
                                <span>{invitation.organization_name}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <Mail className="h-4 w-4 text-[#a78bfa]" />
                                <span>{invitation.email}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <ShieldCheck className="h-4 w-4 text-[#a78bfa]" />
                                <span>Invited by {invitation.invited_by_email || 'your organization owner'}</span>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-[#27272a] bg-[#111111] text-[10px] text-[#a78bfa]">
                                    i
                                </span>
                                <span>Expires {formatDate(invitation.expires_at)}</span>
                            </div>
                        </div>
                    </div>

                    {!isAuthenticated ? (
                        <div className="space-y-4 rounded-2xl border border-[#27272a] bg-[#18181b] p-5 text-sm text-[#a1a1aa]">
                            <p>
                                Sign in or create an account with <span className="text-white">{invitation.email}</span> to
                                accept this invitation.
                            </p>
                            <div className="flex flex-col gap-3">
                                <Link to={loginPath} className={AUTH_PRIMARY_BUTTON_CLASS}>
                                    Sign in to accept
                                </Link>
                                <Link to={signupPath} className={AUTH_GHOST_BUTTON_CLASS}>
                                    Create account
                                </Link>
                            </div>
                        </div>
                    ) : null}

                    {isAuthenticated && user?.organization ? (
                        <div className="rounded-2xl border border-[#27272a] bg-[#18181b] p-4 text-sm leading-6 text-[#a1a1aa]">
                            You are already signed in as <span className="text-white">{user.email}</span> and already belong
                            to an organization. Sign in with a different account to accept this invite.
                        </div>
                    ) : null}

                    {isAuthenticated && !user?.organization && !emailMatches ? (
                        <div className="rounded-2xl border border-[#27272a] bg-[#18181b] p-4 text-sm leading-6 text-[#a1a1aa]">
                            You are signed in as <span className="text-white">{user.email}</span>, but this invitation is for{' '}
                            <span className="text-white">{invitation.email}</span>.
                        </div>
                    ) : null}

                    {statusMessage ? (
                        <div className="rounded-2xl border border-[#27272a] bg-[#18181b] p-4 text-sm leading-6 text-[#a1a1aa]">
                            {statusMessage}
                        </div>
                    ) : null}

                    {canAccept ? (
                        <button
                            type="button"
                            onClick={() => acceptMutation.mutate()}
                            disabled={acceptMutation.isPending}
                            className={AUTH_PRIMARY_BUTTON_CLASS}
                        >
                            {acceptMutation.isPending ? (
                                <>
                                    <ButtonSpinner />
                                    Accepting invitation...
                                </>
                            ) : (
                                'Accept invitation'
                            )}
                        </button>
                    ) : null}

                    <div className="text-center">
                        <Link to="/login" className={AUTH_TEXT_LINK_CLASS}>
                            Back to sign in
                        </Link>
                    </div>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}
