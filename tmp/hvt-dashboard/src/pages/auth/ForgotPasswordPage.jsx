import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Mail } from 'lucide-react';
import { z } from 'zod';
import { toast } from 'sonner';

import { requestPasswordReset } from '@/api/auth';
import {
    AuthCard,
    AuthCardHeader,
    AuthFieldError,
    AuthPageShell,
    AUTH_INPUT_CLASS,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { getErrorMessage } from '@/lib/utils';

const forgotPasswordSchema = z.object({
    email: z.string().email('Enter a valid email address'),
});

export function ForgotPasswordPage() {
    const [submittedEmail, setSubmittedEmail] = useState('');
    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting },
    } = useForm({
        resolver: zodResolver(forgotPasswordSchema),
        defaultValues: {
            email: '',
        },
    });

    useEffect(() => {
        document.title = 'Reset password | HVT';
    }, []);

    const onSubmit = async ({ email }) => {
        try {
            await requestPasswordReset({ email });
            setSubmittedEmail(email);
        } catch (error) {
            toast.error(getErrorMessage(error));
        }
    };

    return (
        <AuthPageShell>
            <AuthCard>
                <AuthCardHeader
                    title="Reset your password"
                    subtitle="Enter your email and we'll send you a reset link."
                />

                <form onSubmit={handleSubmit(onSubmit)} className="mt-8 space-y-4">
                    <div className="space-y-2">
                        <label htmlFor="forgot-password-email" className="text-sm font-medium text-white">
                            Email
                        </label>
                        <input
                            id="forgot-password-email"
                            type="email"
                            autoComplete="email"
                            className={AUTH_INPUT_CLASS}
                            placeholder="you@company.com"
                            {...register('email')}
                        />
                        <AuthFieldError>{errors.email?.message}</AuthFieldError>
                    </div>

                    <button type="submit" disabled={isSubmitting} className={AUTH_PRIMARY_BUTTON_CLASS}>
                        {isSubmitting ? (
                            <>
                                <ButtonSpinner />
                                Sending reset link...
                            </>
                        ) : (
                            'Send reset link'
                        )}
                    </button>
                </form>

                {submittedEmail ? (
                    <div className="mt-4 flex items-start gap-3 rounded-xl border border-[#27272a] bg-[#18181b] px-4 py-3 text-sm text-[#a1a1aa]">
                        <Mail className="mt-0.5 h-4 w-4 shrink-0 text-[#a78bfa]" />
                        <p>
                            If an account exists for <span className="text-white">{submittedEmail}</span>, a reset link
                            has been sent.
                        </p>
                    </div>
                ) : null}

                <div className="mt-6 text-center">
                    <Link to="/login" className={AUTH_TEXT_LINK_CLASS}>
                        Back to sign in
                    </Link>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}

