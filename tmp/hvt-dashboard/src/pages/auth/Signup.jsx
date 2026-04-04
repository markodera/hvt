import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { Eye, EyeOff, Github } from 'lucide-react';
import { z } from 'zod';
import { toast } from 'sonner';

import { listSocialProviders, register as apiRegister } from '@/api/auth';
import {
    AuthCard,
    AuthDivider,
    AuthFieldError,
    AuthPageShell,
    AUTH_GHOST_BUTTON_CLASS,
    AUTH_INPUT_CLASS,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { setPendingVerificationEmail } from '@/lib/emailVerification';
import { markInvitationResumeAfterAuth } from '@/lib/invitations';
import { getErrorMessage } from '@/lib/utils';
import { SOCIAL_AUTH_PROVIDERS, startSocialSignIn } from '@/lib/socialAuth';

const signupSchema = z
    .object({
        full_name: z
            .string()
            .min(3, 'Enter your full name')
            .refine((value) => value.trim().split(/\s+/).length >= 2, 'Enter first and last name'),
        email: z.string().email('Enter a valid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
        confirm_password: z.string().min(1, 'Confirm your password'),
    })
    .refine((data) => data.password === data.confirm_password, {
        message: 'Passwords do not match',
        path: ['confirm_password'],
    });

const chainNodes = ['Org', 'Project', 'API Key', 'Runtime', 'Token'];

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

function splitFullName(value) {
    const pieces = value.trim().split(/\s+/);
    return {
        first_name: pieces[0],
        last_name: pieces.slice(1).join(' '),
    };
}

function ChainDiagram() {
    return (
        <div className="rounded-[20px] border border-[#27272a] bg-[#111111]/88 p-6 transition-colors duration-150 hover:border-[#7c3aed]/60">
            <style>{`
                @keyframes connectorPulse {
                    0%, 100% { opacity: 0.18; }
                    50% { opacity: 0.42; }
                }
            `}</style>
            <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                {chainNodes.map((node, index) => (
                    <div key={node} className="contents">
                        <div className="rounded-full border border-[#3f3f46] bg-[#18181b] px-4 py-2 text-sm font-medium text-[#f4f4f5]">
                            {node}
                        </div>
                        {index < chainNodes.length - 1 ? (
                            <div className="flex h-3 w-10 items-center sm:w-14">
                                <div className="relative h-px w-full overflow-hidden rounded-full bg-[#7c3aed]/15">
                                    <div
                                        className="absolute inset-0 bg-[#7c3aed]/50"
                                        style={{ animation: `connectorPulse 2.8s ease-in-out ${index * 0.2}s infinite` }}
                                    />
                                </div>
                            </div>
                        ) : null}
                    </div>
                ))}
            </div>
        </div>
    );
}

export default function Signup() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const [showPassword, setShowPassword] = useState(false);
    const inviteToken = searchParams.get('invite_token') || '';

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting },
    } = useForm({
        resolver: zodResolver(signupSchema),
        defaultValues: {
            full_name: '',
            email: '',
            password: '',
            confirm_password: '',
        },
    });

    useEffect(() => {
        document.title = 'Sign up | HVT';
    }, []);

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
            const { first_name, last_name } = splitFullName(values.full_name);
            await apiRegister({
                email: values.email,
                password1: values.password,
                password2: values.confirm_password,
                first_name,
                last_name,
            });
            setPendingVerificationEmail(values.email);
            toast.success('Verification email sent.');
            navigate('/verify-email', {
                replace: true,
                state: {
                    email: values.email,
                    inviteToken,
                },
            });
        } catch (error) {
            toast.error(getErrorMessage(error));
        }
    };

    return (
        <AuthPageShell contentClassName="py-6">
            <div className="mx-auto grid w-full max-w-6xl items-stretch gap-6 lg:grid-cols-[1.05fr_0.95fr]">
                <div className="hidden flex-col justify-between rounded-[24px] border border-[#27272a] bg-[#111111]/78 p-8 shadow-[0_32px_80px_rgba(0,0,0,0.35)] backdrop-blur lg:flex">
                    <div className="space-y-10">
                        <Logo />
                        <div className="space-y-5">
                            <div className="inline-flex items-center rounded-full border border-[#27272a] bg-[#18181b] px-3 py-1 text-xs font-medium uppercase tracking-[0.18em] text-[#a1a1aa]">
                                Control plane to runtime
                            </div>
                            <div className="space-y-4">
                                <h1 className="max-w-md text-[2.5rem] font-bold tracking-[-0.04em] text-white">
                                    Build your auth model once and carry it all the way to runtime.
                                </h1>
                                <p className="max-w-lg text-sm leading-7 text-[#a1a1aa]">
                                    Create the control-plane account first, then attach projects, keys, social providers,
                                    and runtime flows without splitting the tenant model across vendors.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="space-y-5">
                        <ChainDiagram />
                        <div className="grid gap-3 sm:grid-cols-2">
                            <div className="rounded-2xl border border-[#27272a] bg-[#18181b]/80 p-4">
                                <div className="text-sm font-semibold text-white">Org and project context</div>
                                <p className="mt-2 text-sm leading-6 text-[#a1a1aa]">
                                    Keep the control plane explicit from the first login instead of retrofitting it into auth later.
                                </p>
                            </div>
                            <div className="rounded-2xl border border-[#27272a] bg-[#18181b]/80 p-4">
                                <div className="text-sm font-semibold text-white">Runtime keys and claims</div>
                                <p className="mt-2 text-sm leading-6 text-[#a1a1aa]">
                                    Issue runtime credentials and flow them straight into project-aware token claims.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <AuthCard className="mx-auto flex w-full max-w-[480px] flex-col justify-center">
                    <div className="space-y-4 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Create account</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                Start with the HVT control plane, then connect projects, keys, and runtime auth from one place.
                            </p>
                        </div>
                    </div>

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
                            <label htmlFor="signup-name" className="text-sm font-medium text-white">
                                Full name
                            </label>
                            <input
                                id="signup-name"
                                type="text"
                                autoComplete="name"
                                className={AUTH_INPUT_CLASS}
                                placeholder="Jane Builder"
                                {...register('full_name')}
                            />
                            <AuthFieldError>{errors.full_name?.message}</AuthFieldError>
                        </div>

                        <div className="space-y-2">
                            <label htmlFor="signup-email" className="text-sm font-medium text-white">
                                Email
                            </label>
                            <input
                                id="signup-email"
                                type="email"
                                autoComplete="email"
                                className={AUTH_INPUT_CLASS}
                                placeholder="you@company.com"
                                {...register('email')}
                            />
                            <AuthFieldError>{errors.email?.message}</AuthFieldError>
                        </div>

                        <div className="space-y-2">
                            <label htmlFor="signup-password" className="text-sm font-medium text-white">
                                Password
                            </label>
                            <div className="relative">
                                <input
                                    id="signup-password"
                                    type={showPassword ? 'text' : 'password'}
                                    autoComplete="new-password"
                                    className={`${AUTH_INPUT_CLASS} pr-11`}
                                    placeholder="Create a password"
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
                        </div>

                        <div className="space-y-2">
                            <label htmlFor="signup-password-confirm" className="text-sm font-medium text-white">
                                Confirm password
                            </label>
                            <input
                                id="signup-password-confirm"
                                type={showPassword ? 'text' : 'password'}
                                autoComplete="new-password"
                                className={AUTH_INPUT_CLASS}
                                placeholder="Repeat your password"
                                {...register('confirm_password')}
                            />
                            <AuthFieldError>{errors.confirm_password?.message}</AuthFieldError>
                        </div>

                        <button type="submit" disabled={isSubmitting} className={AUTH_PRIMARY_BUTTON_CLASS}>
                            {isSubmitting ? (
                                <>
                                    <ButtonSpinner />
                                    Creating account...
                                </>
                            ) : (
                                'Create account'
                            )}
                        </button>
                    </form>

                    <p className="mt-4 text-center text-xs leading-6 text-[#71717a]">
                        By creating an account you agree to our Terms of Service and Privacy Policy.
                    </p>

                    <p className="mt-5 text-center text-sm text-[#a1a1aa]">
                        Already have an account?{' '}
                        <Link to="/login" className="text-white transition-colors hover:text-[#a78bfa]">
                            Sign in
                        </Link>
                    </p>
                </AuthCard>
            </div>
        </AuthPageShell>
    );
}
