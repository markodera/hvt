import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { Eye, EyeOff, Github } from 'lucide-react';
import { z } from 'zod';
import { toast } from 'sonner';

import { listSocialProviders } from '@/api/auth';
import {
    AuthCard,
    AuthCardHeader,
    AuthDivider,
    AuthFieldError,
    AuthPageShell,
    AUTH_GHOST_BUTTON_CLASS,
    AUTH_INPUT_CLASS,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { buildInvitationAcceptPath, consumeInvitationResumeToken, markInvitationResumeAfterAuth } from '@/lib/invitations';
import { getErrorMessage } from '@/lib/utils';
import { SOCIAL_AUTH_PROVIDERS, startSocialSignIn } from '@/lib/socialAuth';
import { useAuth } from '@/hooks/useAuth';

const loginSchema = z.object({
    email: z.string().email('Enter a valid email address'),
    password: z.string().min(1, 'Password is required'),
});

function GoogleIcon() {
    return (
        <svg className="h-4 w-4" viewBox="0 0 24 24" aria-hidden="true">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
        </svg>
    );
}

function extractLockMinutes(detail) {
    if (!detail) return null;
    const match = String(detail).match(/(\d+)\s*(minute|min)/i);
    return match ? Number(match[1]) : null;
}

export default function Login() {
    const navigate = useNavigate();
    const location = useLocation();
    const [searchParams] = useSearchParams();
    const { login } = useAuth();
    const [showPassword, setShowPassword] = useState(false);
    const inviteToken = searchParams.get('invite_token') || '';

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting },
    } = useForm({
        resolver: zodResolver(loginSchema),
        defaultValues: {
            email: '',
            password: '',
        },
    });

    useEffect(() => {
        document.title = 'Sign in | HVT';
    }, []);

    useEffect(() => {
        const toastMessage = location.state?.toastMessage;
        if (toastMessage) {
            toast.success(toastMessage);
            navigate(location.pathname, { replace: true, state: {} });
        }
    }, [location.pathname, location.state, navigate]);

    useEffect(() => {
        if (inviteToken) {
            markInvitationResumeAfterAuth(inviteToken);
        }
    }, [inviteToken]);

    const socialProvidersQuery = useQuery({
        queryKey: ['control-plane-social-providers'],
        queryFn: listSocialProviders,
        retry: 1,
    });

    const providers = useMemo(() => socialProvidersQuery.data?.providers || [], [socialProvidersQuery.data]);

    const handleSocialSignIn = (provider) => {
        const started = startSocialSignIn(provider, providers);
        if (!started) {
            toast.error(`${provider === SOCIAL_AUTH_PROVIDERS.GOOGLE ? 'Google' : 'GitHub'} sign-in is not available yet.`);
        }
    };

    const onSubmit = async (values) => {
        try {
            const me = await login(values);
            const resumeInvitationToken = consumeInvitationResumeToken();

            if (resumeInvitationToken) {
                navigate(buildInvitationAcceptPath(resumeInvitationToken), { replace: true });
                return;
            }

            navigate(me?.organization ? '/dashboard' : '/dashboard/create-organization', { replace: true });
        } catch (error) {
            const detail = getErrorMessage(error);
            const status = error?.response?.status;
            const code = error?.response?.data?.code || '';

            if (status === 429 || /locked/i.test(detail) || /locked/i.test(code)) {
                navigate('/account-locked', {
                    replace: true,
                    state: {
                        detail,
                        minutes: extractLockMinutes(detail),
                    },
                });
                return;
            }

            toast.error(detail);
        }
    };

    return (
        <AuthPageShell>
            <AuthCard>
                <AuthCardHeader
                    title="Sign in"
                    subtitle="Use your HVT account to access your organization, projects, keys, and runtime settings."
                />

                <div className="mt-8 space-y-4">
                    <button
                        type="button"
                        onClick={() => handleSocialSignIn(SOCIAL_AUTH_PROVIDERS.GOOGLE)}
                        disabled={socialProvidersQuery.isLoading}
                        className={AUTH_GHOST_BUTTON_CLASS}
                    >
                        <GoogleIcon />
                        Continue with Google
                    </button>
                    <button
                        type="button"
                        onClick={() => handleSocialSignIn(SOCIAL_AUTH_PROVIDERS.GITHUB)}
                        disabled={socialProvidersQuery.isLoading}
                        className={AUTH_GHOST_BUTTON_CLASS}
                    >
                        <Github className="h-4 w-4" />
                        Continue with GitHub
                    </button>
                </div>

                <div className="my-6">
                    <AuthDivider />
                </div>

                <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                    <div className="space-y-2">
                        <label htmlFor="login-email" className="text-sm font-medium text-white">
                            Email
                        </label>
                        <input
                            id="login-email"
                            type="email"
                            autoComplete="email"
                            className={AUTH_INPUT_CLASS}
                            placeholder="you@company.com"
                            {...register('email')}
                        />
                        <AuthFieldError>{errors.email?.message}</AuthFieldError>
                    </div>

                    <div className="space-y-2">
                        <label htmlFor="login-password" className="text-sm font-medium text-white">
                            Password
                        </label>
                        <div className="relative">
                            <input
                                id="login-password"
                                type={showPassword ? 'text' : 'password'}
                                autoComplete="current-password"
                                className={`${AUTH_INPUT_CLASS} pr-11`}
                                placeholder="Enter your password"
                                {...register('password')}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword((current) => !current)}
                                className="absolute inset-y-0 right-0 inline-flex w-11 items-center justify-center text-[#71717a] transition-colors hover:text-white"
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                            </button>
                        </div>
                        <AuthFieldError>{errors.password?.message}</AuthFieldError>
                        <div className="flex justify-end">
                            <Link to="/forgot-password" className={AUTH_TEXT_LINK_CLASS}>
                                Forgot password?
                            </Link>
                        </div>
                    </div>

                    <button type="submit" disabled={isSubmitting} className={AUTH_PRIMARY_BUTTON_CLASS}>
                        {isSubmitting ? (
                            <>
                                <ButtonSpinner />
                                Signing in...
                            </>
                        ) : (
                            'Sign in'
                        )}
                    </button>
                </form>

                <p className="mt-6 text-center text-sm text-[#a1a1aa]">
                    Don&apos;t have an account?{' '}
                    <Link to="/signup" className="text-white transition-colors hover:text-[#a78bfa]">
                        Get started free
                    </Link>
                </p>
            </AuthCard>
        </AuthPageShell>
    );
}
