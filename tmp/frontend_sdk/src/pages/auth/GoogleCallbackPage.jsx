import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { AlertCircle } from 'lucide-react';

import { socialAuthGoogle } from '@/api/auth';
import { useAuth } from '@/hooks/useAuth';
import { hvt } from '@/lib/hvt';
import {
    SOCIAL_AUTH_ENDPOINTS,
    SOCIAL_AUTH_PROVIDERS,
    clearPendingSocialAuth,
    logSocialAuthTelemetry,
    validateSocialCallback,
} from '@/lib/socialAuth';
import { buildInvitationAcceptPath, consumeInvitationResumeToken } from '@/lib/invitations';

const DOT_GRID_STYLE = {
    backgroundImage:
        'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
    backgroundRepeat: 'repeat',
};

function delay(ms) {
    return new Promise((resolve) => {
        window.setTimeout(resolve, ms);
    });
}

async function tryResolveSession(waitForSession) {
    try {
        const refreshed = await hvt.auth.refresh();
        if (refreshed?.access) {
            hvt.setAccessToken(refreshed.access);
        }
    } catch (error) {
        // The refresh endpoint now resets cookies correctly, but it may still miss
        // during the first callback tick. The retry loop handles this case.
    }

    return waitForSession({ attempts: 1, delayMs: 0 });
}

async function resolveSessionWithRetries(waitForSession) {
    let lastError = null;

    for (let attempt = 0; attempt < 4; attempt += 1) {
        if (attempt > 0) {
            await delay(500);
        }

        try {
            return await tryResolveSession(waitForSession);
        } catch (error) {
            lastError = error;
        }
    }

    throw lastError;
}

function CallbackStatus({ error }) {
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

            <div className="relative mx-auto flex min-h-[calc(100vh-5rem)] max-w-xl items-center justify-center">
                <div className="w-full rounded-2xl border border-[#27272a] bg-[#111111]/90 p-8 text-center shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur">
                    {!error ? (
                        <>
                            <div className="mx-auto flex w-fit items-center gap-2 rounded-full border border-[#27272a] bg-[#18181b] px-4 py-2 text-xs font-medium uppercase tracking-[0.18em] text-[#a1a1aa]">
                                <span className="h-2 w-2 rounded-full bg-[#7c3aed] animate-pulse" />
                                Social auth
                            </div>
                            <h1 className="mt-6 text-2xl font-bold tracking-[-0.03em] text-white">Finishing sign-in...</h1>
                            <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                                We are verifying your refreshed session before opening the dashboard.
                            </p>
                            <div className="mx-auto mt-8 h-1.5 w-40 overflow-hidden rounded-full bg-[#1c1c1f]">
                                <div className="h-full w-1/2 animate-pulse rounded-full bg-[#7c3aed]/60" />
                            </div>
                        </>
                    ) : (
                        <>
                            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-[#3f3f46] bg-[#18181b] text-[#f4f4f5]">
                                <AlertCircle className="h-5 w-5 text-[#a78bfa]" />
                            </div>
                            <h1 className="mt-6 text-2xl font-bold tracking-[-0.03em] text-white">We couldn&apos;t finish sign-in.</h1>
                            <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">{error}</p>
                            <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
                                <Link
                                    to="/login"
                                    className="inline-flex h-10 items-center justify-center rounded-md border border-[#27272a] bg-transparent px-4 text-sm font-semibold text-white transition-colors hover:bg-[#18181b]"
                                >
                                    Back to login
                                </Link>
                                <Link
                                    to="/signup"
                                    className="inline-flex h-10 items-center justify-center rounded-md bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors hover:bg-[#6d28d9]"
                                >
                                    Create an account
                                </Link>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}

export function GoogleCallbackPage() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const { waitForSession } = useAuth();
    const [error, setError] = useState('');

    useEffect(() => {
        let cancelled = false;

        async function finishSignIn() {
            const code = searchParams.get('code');
            const callbackState = searchParams.get('state');

            if (!code) {
                clearPendingSocialAuth();
                setError('No authorization code was returned by Google.');
                return;
            }

            const validation = validateSocialCallback({
                expectedProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                callbackState,
            });

            if (!validation.isValid) {
                clearPendingSocialAuth();
                setError('Google sign-in could not be verified. Please try again.');
                return;
            }

            try {
                await socialAuthGoogle({
                    code,
                    callback_url: `${window.location.origin}/auth/google/callback`,
                });

                logSocialAuthTelemetry({
                    selectedProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    callbackProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    endpointHit: SOCIAL_AUTH_ENDPOINTS[SOCIAL_AUTH_PROVIDERS.GOOGLE],
                    httpStatus: 200,
                    errorDetail: null,
                    stage: 'exchange_complete',
                });
            } catch (exchangeError) {
                logSocialAuthTelemetry({
                    selectedProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    callbackProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    endpointHit: SOCIAL_AUTH_ENDPOINTS[SOCIAL_AUTH_PROVIDERS.GOOGLE],
                    httpStatus: exchangeError?.status ?? exchangeError?.response?.status ?? null,
                    errorDetail: exchangeError?.detail || exchangeError?.response?.data?.detail || '',
                    stage: 'exchange_failed',
                });
                clearPendingSocialAuth();
                if (!cancelled) {
                    setError('Google sign-in failed. Please try again.');
                }
                return;
            }

            try {
                await resolveSessionWithRetries(waitForSession);

                const resumeInvitationToken = consumeInvitationResumeToken();
                clearPendingSocialAuth();

                if (cancelled) {
                    return;
                }

                if (resumeInvitationToken) {
                    navigate(buildInvitationAcceptPath(resumeInvitationToken), { replace: true });
                    return;
                }

                navigate('/dashboard', { replace: true });
            } catch (sessionError) {
                logSocialAuthTelemetry({
                    selectedProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    callbackProvider: SOCIAL_AUTH_PROVIDERS.GOOGLE,
                    endpointHit: SOCIAL_AUTH_ENDPOINTS[SOCIAL_AUTH_PROVIDERS.GOOGLE],
                    httpStatus: sessionError?.status ?? sessionError?.response?.status ?? null,
                    errorDetail: sessionError?.detail || sessionError?.response?.data?.detail || '',
                    stage: 'session_resolve_failed',
                });
                clearPendingSocialAuth();
                if (!cancelled) {
                    setError('Your sign-in completed, but the session could not be confirmed. Please try again.');
                }
            }
        }

        finishSignIn();

        return () => {
            cancelled = true;
        };
    }, [navigate, searchParams, waitForSession]);

    return <CallbackStatus error={error} />;
}
