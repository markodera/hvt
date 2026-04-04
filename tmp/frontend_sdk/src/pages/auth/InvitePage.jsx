import { useEffect, useMemo } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Mail, ShieldCheck, Users } from 'lucide-react';
import { toast } from 'sonner';

import { acceptOrganizationInvitation, lookupOrganizationInvitation } from '@/api/organizations';
import { useAuth } from '@/hooks/useAuth';
import {
    buildInvitationAuthPath,
    clearPendingInvitationToken,
    setPendingInvitationToken,
} from '@/lib/invitations';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { LoadingSpinner } from '@/components/LoadingSpinner';
import { Logo } from '@/components/Logo';
import { formatDate, getErrorMessage } from '@/lib/utils';

function statusVariant(status) {
    if (status === 'accepted') return 'success';
    if (status === 'revoked' || status === 'expired') return 'warning';
    return 'secondary';
}

function InviteBackground() {
    return (
        <>
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
                style={{
                    background:
                        'radial-gradient(circle at top center, rgba(124,58,237,0.15), transparent 56%)',
                }}
            />
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
                style={{
                    backgroundImage:
                        'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
                    backgroundRepeat: 'repeat',
                    WebkitMaskImage:
                        'linear-gradient(to bottom, rgba(0,0,0,0.92) 0%, rgba(0,0,0,0.88) 68%, transparent 100%)',
                    maskImage:
                        'linear-gradient(to bottom, rgba(0,0,0,0.92) 0%, rgba(0,0,0,0.88) 68%, transparent 100%)',
                }}
            />
        </>
    );
}

function Wordmark() {
    return <Logo href="/" align="center" className="mx-auto" />;
}

export function InvitePage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const { user, isAuthenticated, isLoading: authLoading, refreshSession } = useAuth();
    const token = useMemo(() => (searchParams.get('token') || '').trim(), [searchParams]);

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
            await refreshSession();
            clearPendingInvitationToken();
            toast.success(`You've joined ${invitation?.organization_name || 'the organization'} as ${invitation?.role || 'member'}`);
            navigate('/dashboard');
        },
        onError: (mutationError) => {
            toast.error(getErrorMessage(mutationError));
        },
    });

    if (!token) {
        return (
            <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-white">
                <InviteBackground />
                <div className="relative mx-auto flex min-h-screen max-w-[440px] items-center justify-center px-4 py-10">
                    <div className="w-full rounded-[20px] border border-[#27272a] bg-[#111111]/92 p-8 backdrop-blur-sm sm:p-10">
                        <div className="flex justify-center">
                            <Wordmark />
                        </div>
                        <p className="mt-8 text-center text-sm text-[#a1a1aa]">No invitation token was provided.</p>
                        <div className="mt-6 flex justify-center">
                            <Button asChild variant="outline">
                                <Link to="/login">Back to login</Link>
                            </Button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    if (authLoading || isLoading) {
        return (
            <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-white">
                <InviteBackground />
                <div className="relative mx-auto flex min-h-screen max-w-[440px] items-center justify-center px-4 py-10">
                    <div className="w-full rounded-[20px] border border-[#27272a] bg-[#111111]/92 p-8 backdrop-blur-sm sm:p-10">
                        <div className="flex justify-center">
                            <Wordmark />
                        </div>
                        <div className="mt-8 flex flex-col items-center gap-4 py-10 text-center">
                            <LoadingSpinner size="lg" />
                            <p className="text-sm text-[#a1a1aa]">Loading invitation details...</p>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    if (isError || !invitation) {
        return (
            <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-white">
                <InviteBackground />
                <div className="relative mx-auto flex min-h-screen max-w-[440px] items-center justify-center px-4 py-10">
                    <div className="w-full rounded-[20px] border border-[#27272a] bg-[#111111]/92 p-8 backdrop-blur-sm sm:p-10">
                        <div className="flex justify-center">
                            <Wordmark />
                        </div>
                        <p className="mt-8 text-center text-sm text-[#a1a1aa]">{getErrorMessage(error)}</p>
                        <div className="mt-6 flex justify-center">
                            <Button asChild variant="outline">
                                <Link to="/login">Back to login</Link>
                            </Button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    const loginPath = buildInvitationAuthPath('/login', token);
    const registerPath = buildInvitationAuthPath('/signup', token);
    const signedInEmail = user?.email?.toLowerCase() || '';
    const invitationEmail = invitation.email?.toLowerCase() || '';
    const emailMatches = signedInEmail && invitationEmail && signedInEmail === invitationEmail;
    const canAccept = isAuthenticated && !user?.organization && emailMatches && invitation.status === 'pending';

    return (
        <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-white">
            <InviteBackground />

            <div className="relative flex min-h-screen items-center justify-center px-4 py-10 sm:px-6">
                <div className="w-full max-w-[440px] rounded-[20px] border border-[#27272a] bg-[#111111]/92 p-8 backdrop-blur-sm transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] sm:p-10">
                    <div className="flex justify-center">
                        <Wordmark />
                    </div>

                    <div className="mt-8 text-center">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Join {invitation.organization_name}</h1>
                        <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                            This invitation adds you to the organization control plane as a {invitation.role}.
                        </p>
                    </div>

                    <div className="mt-8 space-y-4 rounded-xl border border-[#27272a] bg-[#18181b] p-5">
                        <div className="flex flex-wrap items-center gap-2">
                            <Badge variant={statusVariant(invitation.status)}>{invitation.status}</Badge>
                            <Badge variant={invitation.role === 'admin' ? 'default' : 'secondary'}>{invitation.role}</Badge>
                        </div>
                        <div className="grid gap-3 text-sm text-[#a1a1aa]">
                            <p className="flex items-center gap-2">
                                <Mail className="h-4 w-4 text-[#a78bfa]" />
                                {invitation.email}
                            </p>
                            {invitation.invited_by_email ? (
                                <p className="flex items-center gap-2">
                                    <Users className="h-4 w-4 text-[#a78bfa]" />
                                    Invited by {invitation.invited_by_email}
                                </p>
                            ) : null}
                            <p className="flex items-center gap-2">
                                <ShieldCheck className="h-4 w-4 text-[#a78bfa]" />
                                Expires {formatDate(invitation.expires_at)}
                            </p>
                        </div>

                        {!isAuthenticated && (
                            <div className="space-y-3 rounded-xl border border-[#27272a] bg-[#111111] p-4">
                                <p className="text-sm text-[#a1a1aa]">
                                    Sign in or create an account with <span className="font-medium text-white">{invitation.email}</span> to accept this invitation.
                                </p>
                                <div className="flex flex-col gap-3 sm:flex-row">
                                    <Button asChild className="flex-1">
                                        <Link to={loginPath}>Sign in to accept</Link>
                                    </Button>
                                    <Button asChild variant="outline" className="flex-1">
                                        <Link to={registerPath}>Create account</Link>
                                    </Button>
                                </div>
                            </div>
                        )}

                        {isAuthenticated && user?.organization && (
                            <div className="rounded-xl border border-[#27272a] bg-[#111111] p-4 text-sm text-[#a1a1aa]">
                                You are already signed in as <span className="font-medium text-white">{user.email}</span> and already belong to an organization. Sign in with a different account to accept this invite.
                            </div>
                        )}

                        {isAuthenticated && !user?.organization && !emailMatches && (
                            <div className="rounded-xl border border-[#27272a] bg-[#111111] p-4 text-sm text-[#a1a1aa]">
                                You are signed in as <span className="font-medium text-white">{user.email}</span>, but this invitation is for <span className="font-medium text-white">{invitation.email}</span>.
                            </div>
                        )}

                        {invitation.status !== 'pending' && (
                            <div className="rounded-xl border border-[#27272a] bg-[#111111] p-4 text-sm text-[#a1a1aa]">
                                This invitation is no longer pending, so it cannot be accepted.
                            </div>
                        )}

                        {canAccept && (
                            <Button onClick={() => acceptMutation.mutate()} disabled={acceptMutation.isPending} className="w-full">
                                {acceptMutation.isPending ? 'Accepting...' : 'Accept invitation'}
                            </Button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default InvitePage;
