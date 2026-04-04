import { useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Info, Mail, ShieldCheck, Users } from 'lucide-react';
import { toast } from 'sonner';

import { acceptOrganizationInvitation, lookupOrganizationInvitation } from '@/api/organizations';
import { useAuth } from '@/hooks/useAuth';
import {
    buildInvitationAuthPath,
    clearPendingInvitationToken,
    setPendingInvitationToken,
} from '@/lib/invitations';
import { getErrorMessage } from '@/lib/utils';

const DOT_GRID_STYLE = {
    backgroundImage:
        'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
    backgroundRepeat: 'repeat',
};

function statusClass(status) {
    if (status === 'accepted') return 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    if (status === 'revoked' || status === 'expired') return 'border border-rose-500/30 bg-rose-500/10 text-rose-300';
    return 'border border-[#7c3aed]/40 bg-[#7c3aed]/10 text-[#c4b5fd]';
}

function roleClass(role) {
    return role === 'admin'
        ? 'border border-[#7c3aed]/40 bg-[#7c3aed]/10 text-[#c4b5fd]'
        : 'border border-[#27272a] bg-[#18181b] text-[#a1a1aa]';
}

function InviteCard({ children }) {
    return (
        <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] px-6 py-10 text-white">
            <div
                className="pointer-events-none absolute inset-0 opacity-70"
                style={{
                    ...DOT_GRID_STYLE,
                    maskImage: 'linear-gradient(to bottom, rgba(255,255,255,0.95), rgba(255,255,255,0.3))',
                    WebkitMaskImage: 'linear-gradient(to bottom, rgba(255,255,255,0.95), rgba(255,255,255,0.3))',
                }}
            />
            <div
                className="pointer-events-none absolute inset-x-0 top-0 h-[32rem]"
                style={{
                    background:
                        'radial-gradient(circle at 50% 0%, rgba(124,58,237,0.14), rgba(124,58,237,0.03) 35%, transparent 70%)',
                }}
            />

            <div className="relative mx-auto flex min-h-[calc(100vh-5rem)] max-w-lg items-center justify-center">
                <div className="w-full rounded-2xl border border-[#27272a] bg-[#111111]/92 p-8 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur">
                    <Link to="/" className="inline-flex items-center gap-2 text-white">
                        <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-[#5b21b6] font-mono text-sm font-bold">
                            H
                        </span>
                        <span className="font-mono text-base font-bold tracking-[-0.03em]">HVT</span>
                    </Link>
                    <div className="mt-8">{children}</div>
                </div>
            </div>
        </div>
    );
}

export function InvitationAcceptPage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const token = (searchParams.get('token') || '').trim();
    const { user, isAuthenticated, isLoading: authLoading, refreshSession } = useAuth();

    useEffect(() => {
        if (token) {
            setPendingInvitationToken(token);
        }
    }, [token]);

    const { data: invitation, isLoading, isError, error } = useQuery({
        queryKey: ['invitationLookup', token],
        queryFn: () => lookupOrganizationInvitation(token),
        enabled: Boolean(token),
        retry: false,
    });

    const acceptMutation = useMutation({
        mutationFn: () => acceptOrganizationInvitation(token),
        onSuccess: async () => {
            await refreshSession({ clearOnError: false });
            clearPendingInvitationToken();
            toast.success(`You've joined ${invitation.organization_name} as ${invitation.role}`);
            navigate('/dashboard', { replace: true });
        },
        onError: () => {
            // Error is rendered in-page to keep the flow calm and explicit.
        },
    });

    if (!token) {
        return (
            <InviteCard>
                <h1 className="text-2xl font-bold tracking-[-0.03em] text-white">Invitation link missing</h1>
                <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                    This invite link does not include a token. Ask the organisation owner to resend the invitation.
                </p>
                <div className="mt-8">
                    <Link
                        to="/login"
                        className="inline-flex h-10 items-center justify-center rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                    >
                        Back to login
                    </Link>
                </div>
            </InviteCard>
        );
    }

    if (authLoading || isLoading) {
        return (
            <InviteCard>
                <h1 className="text-2xl font-bold tracking-[-0.03em] text-white">Loading invitation...</h1>
                <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                    We&apos;re checking this invitation and your current session.
                </p>
            </InviteCard>
        );
    }

    if (isError || !invitation) {
        return (
            <InviteCard>
                <h1 className="text-2xl font-bold tracking-[-0.03em] text-white">This invitation can&apos;t be opened</h1>
                <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">{getErrorMessage(error)}</p>
                <div className="mt-6 rounded-xl border border-[#27272a] bg-[#18181b] px-4 py-3 text-sm text-[#a1a1aa]">
                    Need help? Contact <a className="text-white" href="mailto:support@hvts.app">support@hvts.app</a>
                </div>
            </InviteCard>
        );
    }

    const loginPath = buildInvitationAuthPath('/login', token);
    const signupPath = buildInvitationAuthPath('/signup', token);
    const invitationEmail = invitation.email?.toLowerCase() || '';
    const signedInEmail = user?.email?.toLowerCase() || '';
    const emailMatches = invitationEmail && signedInEmail && invitationEmail === signedInEmail;
    const alreadyScoped = Boolean(user?.organization);
    const canAccept = isAuthenticated && emailMatches && !alreadyScoped && invitation.status === 'pending';
    const inviterLabel = invitation.invited_by_email || 'Organisation admin';

    return (
        <InviteCard>
            <div className="text-center">
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#7c3aed]/30 bg-[#7c3aed]/10 text-[#a78bfa]">
                    <Users className="h-7 w-7" />
                </div>
                <h1 className="mt-6 text-2xl font-bold tracking-[-0.03em] text-white">
                    Join {invitation.organization_name}
                </h1>
                <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                    Accept this invite to join the organisation control plane.
                </p>
            </div>

            <div className="mt-8 space-y-4 rounded-2xl border border-[#27272a] bg-[#18181b] p-5">
                <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${statusClass(invitation.status)}`}>
                        {invitation.status}
                    </span>
                    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${roleClass(invitation.role)}`}>
                        {invitation.role}
                    </span>
                </div>

                <div className="space-y-3 text-sm text-[#a1a1aa]">
                    <p className="flex items-center gap-2">
                        <Mail className="h-4 w-4 text-[#a78bfa]" />
                        {invitation.email}
                    </p>
                    <p className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-[#a78bfa]" />
                        Invited by {inviterLabel}
                    </p>
                    <p className="flex items-center gap-2">
                        <Info className="h-4 w-4 text-[#a78bfa]" />
                        Expires {new Date(invitation.expires_at).toLocaleString()}
                    </p>
                </div>

                {!isAuthenticated ? (
                    <div className="space-y-3 rounded-xl border border-[#27272a] bg-[#111111] p-4">
                        <p className="text-sm text-[#a1a1aa]">
                            Sign in or create an account with <span className="text-white">{invitation.email}</span> to accept this invitation.
                        </p>
                        <div className="flex flex-col gap-3 sm:flex-row">
                            <Link
                                to={loginPath}
                                className="inline-flex h-10 flex-1 items-center justify-center rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                            >
                                Sign in
                            </Link>
                            <Link
                                to={signupPath}
                                className="inline-flex h-10 flex-1 items-center justify-center rounded-md border border-[#27272a] bg-transparent px-4 text-sm font-semibold text-white transition-colors hover:bg-[#18181b]"
                            >
                                Create account
                            </Link>
                        </div>
                    </div>
                ) : null}

                {isAuthenticated && alreadyScoped ? (
                    <div className="rounded-xl border border-[#27272a] bg-[#111111] px-4 py-3 text-sm text-[#a1a1aa]">
                        You are already signed in to an organisation. Launch remains single-org, so this invite must be accepted with a different account.
                    </div>
                ) : null}

                {isAuthenticated && !alreadyScoped && !emailMatches ? (
                    <div className="rounded-xl border border-[#27272a] bg-[#111111] px-4 py-3 text-sm text-[#a1a1aa]">
                        You are signed in as <span className="text-white">{user.email}</span>, but this invitation is for <span className="text-white">{invitation.email}</span>.
                    </div>
                ) : null}

                {acceptMutation.isError ? (
                    <div className="rounded-xl border border-rose-500/25 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
                        <p>{getErrorMessage(acceptMutation.error)}</p>
                        <p className="mt-2 text-rose-100/80">
                            Need help? Contact <a className="underline" href="mailto:support@hvts.app">support@hvts.app</a>
                        </p>
                    </div>
                ) : null}

                {canAccept ? (
                    <button
                        type="button"
                        onClick={() => acceptMutation.mutate()}
                        disabled={acceptMutation.isPending}
                        className="inline-flex h-10 w-full items-center justify-center rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9] disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        {acceptMutation.isPending ? 'Joining...' : `Join ${invitation.organization_name}`}
                    </button>
                ) : null}
            </div>
        </InviteCard>
    );
}
