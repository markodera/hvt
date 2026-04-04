import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Check, Eye, EyeOff, LockKeyhole, ShieldAlert } from 'lucide-react';
import { z } from 'zod';
import { toast } from 'sonner';

import { confirmPasswordReset, validatePasswordResetToken } from '@/api/auth';
import {
    AuthCard,
    AuthFieldError,
    AuthPageShell,
    AUTH_INPUT_CLASS,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { getErrorMessage } from '@/lib/utils';

const resetPasswordSchema = z
    .object({
        new_password1: z.string().min(8, 'Password must be at least 8 characters'),
        new_password2: z.string().min(1, 'Confirm your new password'),
    })
    .refine((data) => data.new_password1 === data.new_password2, {
        message: 'Passwords do not match',
        path: ['new_password2'],
    });

function parseResetToken(rawToken, routeUid, routeToken) {
    if (routeUid && routeToken) {
        return { uid: routeUid, token: routeToken, isValid: true };
    }

    const normalized = (rawToken || '').trim().replace(/^\/+|\/+$/g, '');
    if (!normalized) {
        return { uid: '', token: '', isValid: false };
    }

    const parts = normalized.split('/');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return { uid: '', token: '', isValid: false };
    }

    return {
        uid: parts[0],
        token: parts[1],
        isValid: true,
    };
}

function buildPasswordChecks(password) {
    return {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        number: /\d/.test(password),
        bonus: password.length >= 12 || /[^A-Za-z0-9]/.test(password),
    };
}

function getStrengthVisuals(password) {
    const checks = buildPasswordChecks(password);
    const score = Object.values(checks).filter(Boolean).length;

    if (!password) {
        return { score: 0, color: '#27272a' };
    }

    if (score <= 1) {
        return { score, color: '#ef4444' };
    }

    if (score <= 3) {
        return { score, color: '#f59e0b' };
    }

    return { score, color: '#22c55e' };
}

function isTokenInvalidError(error) {
    const data = error?.response?.data;
    if (data?.uid || data?.token) {
        return true;
    }

    const detail = getErrorMessage(error).toLowerCase();
    return detail.includes('invalid') || detail.includes('expired') || detail.includes('used');
}

function ExpiredResetState({ message }) {
    return (
        <AuthCard>
            <div className="space-y-6 text-center">
                <Logo align="center" className="mx-auto" />
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#7f1d1d] bg-[#1f1416] text-[#f87171]">
                    <ShieldAlert className="h-7 w-7" />
                </div>
                <div className="space-y-2">
                    <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Link expired</h1>
                    <p className="text-sm leading-6 text-[#a1a1aa]">
                        {message || 'This reset link has expired or already been used.'}
                    </p>
                </div>
                <Link to="/forgot-password" className={AUTH_PRIMARY_BUTTON_CLASS}>
                    Request a new link
                </Link>
            </div>
        </AuthCard>
    );
}

export function ResetPasswordPage() {
    const navigate = useNavigate();
    const params = useParams();
    const [searchParams] = useSearchParams();
    const [showPassword, setShowPassword] = useState(false);
    const [status, setStatus] = useState('loading');
    const [expiredMessage, setExpiredMessage] = useState('');

    const parsedToken = useMemo(
        () => parseResetToken(searchParams.get('token'), params.uid, params.token),
        [params.token, params.uid, searchParams],
    );

    const {
        register,
        handleSubmit,
        watch,
        formState: { errors, isSubmitting },
    } = useForm({
        resolver: zodResolver(resetPasswordSchema),
        defaultValues: {
            new_password1: '',
            new_password2: '',
        },
    });

    const password = watch('new_password1') || '';
    const confirmPassword = watch('new_password2') || '';
    const checks = useMemo(() => buildPasswordChecks(password), [password]);
    const strength = useMemo(() => getStrengthVisuals(password), [password]);
    const passwordsMatch = password && confirmPassword && password === confirmPassword;
    const isAcceptableStrength = checks.length && checks.uppercase && checks.number;

    useEffect(() => {
        document.title = 'Set new password | HVT';
    }, []);

    useEffect(() => {
        let cancelled = false;

        async function validateToken() {
            if (!parsedToken.isValid) {
                setStatus('expired');
                setExpiredMessage('This reset link is invalid or incomplete.');
                return;
            }

            try {
                await validatePasswordResetToken({
                    uid: parsedToken.uid,
                    token: parsedToken.token,
                });
                if (!cancelled) {
                    setStatus('ready');
                }
            } catch (error) {
                if (!cancelled) {
                    setStatus('expired');
                    setExpiredMessage(getErrorMessage(error));
                }
            }
        }

        validateToken();

        return () => {
            cancelled = true;
        };
    }, [parsedToken]);

    const onSubmit = async (values) => {
        try {
            await confirmPasswordReset(
                {
                    uid: parsedToken.uid,
                    token: parsedToken.token,
                },
                values,
            );
            toast.success('Password updated. Sign in with your new password.');
            navigate('/login', {
                replace: true,
                state: {
                    toastMessage: 'Password updated. Sign in with your new password.',
                },
            });
        } catch (error) {
            if (isTokenInvalidError(error)) {
                setStatus('expired');
                setExpiredMessage(getErrorMessage(error));
                return;
            }
            toast.error(getErrorMessage(error));
        }
    };

    if (status === 'loading') {
        return (
            <AuthPageShell>
                <AuthCard>
                    <div className="space-y-6 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a78bfa]">
                            <LockKeyhole className="h-7 w-7" />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Set new password</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                Validating your reset link...
                            </p>
                        </div>
                    </div>
                </AuthCard>
            </AuthPageShell>
        );
    }

    if (status === 'expired') {
        return (
            <AuthPageShell>
                <ExpiredResetState message={expiredMessage} />
            </AuthPageShell>
        );
    }

    return (
        <AuthPageShell>
            <AuthCard>
                <div className="space-y-6">
                    <div className="space-y-4 text-center">
                        <Logo align="center" className="mx-auto" />
                        <div className="space-y-2">
                            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Set new password</h1>
                            <p className="text-sm leading-6 text-[#a1a1aa]">
                                Choose a strong password for your HVT account.
                            </p>
                        </div>
                    </div>

                    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                        <div className="space-y-2">
                            <label htmlFor="reset-password-new" className="text-sm font-medium text-white">
                                New password
                            </label>
                            <div className="relative">
                                <input
                                    id="reset-password-new"
                                    type={showPassword ? 'text' : 'password'}
                                    autoComplete="new-password"
                                    className={`${AUTH_INPUT_CLASS} pr-11`}
                                    placeholder="Create a new password"
                                    {...register('new_password1')}
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
                            <AuthFieldError>{errors.new_password1?.message}</AuthFieldError>
                        </div>

                        <div className="flex gap-2">
                            {Array.from({ length: 4 }).map((_, index) => (
                                <span
                                    key={`strength-${index + 1}`}
                                    className="h-1.5 flex-1 rounded-full transition-colors duration-150"
                                    style={{
                                        backgroundColor: index < strength.score ? strength.color : '#27272a',
                                    }}
                                />
                            ))}
                        </div>

                        <div className="space-y-2 rounded-xl border border-[#27272a] bg-[#18181b] p-4">
                            {[
                                ['At least 8 characters', checks.length],
                                ['One uppercase letter', checks.uppercase],
                                ['One number', checks.number],
                            ].map(([label, passed]) => (
                                <div key={label} className="flex items-center gap-2 text-sm">
                                    <span
                                        className={`inline-flex h-5 w-5 items-center justify-center rounded-full border ${
                                            passed
                                                ? 'border-[#14532d] bg-[#052e16] text-[#4ade80]'
                                                : 'border-[#27272a] bg-[#111111] text-[#71717a]'
                                        }`}
                                    >
                                        <Check className="h-3 w-3" />
                                    </span>
                                    <span className={passed ? 'text-white' : 'text-[#a1a1aa]'}>{label}</span>
                                </div>
                            ))}
                        </div>

                        <div className="space-y-2">
                            <label htmlFor="reset-password-confirm" className="text-sm font-medium text-white">
                                Confirm password
                            </label>
                            <input
                                id="reset-password-confirm"
                                type={showPassword ? 'text' : 'password'}
                                autoComplete="new-password"
                                className={AUTH_INPUT_CLASS}
                                placeholder="Repeat your new password"
                                {...register('new_password2')}
                            />
                            <AuthFieldError>{errors.new_password2?.message}</AuthFieldError>
                        </div>

                        <button
                            type="submit"
                            disabled={isSubmitting || !passwordsMatch || !isAcceptableStrength}
                            className={AUTH_PRIMARY_BUTTON_CLASS}
                        >
                            {isSubmitting ? (
                                <>
                                    <ButtonSpinner />
                                    Resetting password...
                                </>
                            ) : (
                                'Reset password'
                            )}
                        </button>
                    </form>

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

