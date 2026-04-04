import { useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { verifyEmail } from '@/api/auth';
import { AuthCard, AuthPageShell } from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { clearPendingVerificationEmail, getPendingVerificationEmail } from '@/lib/emailVerification';
import { getErrorMessage } from '@/lib/utils';

export function VerifyEmailPage() {
    const navigate = useNavigate();
    const { key } = useParams();

    useEffect(() => {
        document.title = 'Verifying email | HVT';
    }, []);

    useEffect(() => {
        let cancelled = false;

        async function finishVerification() {
            if (!key) {
                navigate('/verify-email/expired', {
                    replace: true,
                    state: {
                        email: getPendingVerificationEmail(),
                        message: 'No verification key was provided.',
                    },
                });
                return;
            }

            try {
                await verifyEmail(key);
                clearPendingVerificationEmail();
                if (!cancelled) {
                    navigate('/verify-email/success', { replace: true });
                }
            } catch (error) {
                if (!cancelled) {
                    navigate('/verify-email/expired', {
                        replace: true,
                        state: {
                            email: getPendingVerificationEmail(),
                            message: getErrorMessage(error),
                        },
                    });
                }
            }
        }

        finishVerification();

        return () => {
            cancelled = true;
        };
    }, [key, navigate]);

    return (
        <AuthPageShell>
            <AuthCard>
                <div className="space-y-6 text-center">
                    <Logo align="center" className="mx-auto" />
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a78bfa]">
                        <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-[#7c3aed]" />
                    </div>
                    <div className="space-y-2">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Verifying your email</h1>
                        <p className="text-sm leading-6 text-[#a1a1aa]">
                            We&apos;re validating your verification link now.
                        </p>
                    </div>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}

