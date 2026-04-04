import { useEffect, useMemo, useState } from 'react';
import { Check, Mail } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { toast } from 'sonner';

import { resendVerificationEmail } from '@/api/auth';
import {
    AuthCard,
    AuthPageShell,
    AUTH_PRIMARY_BUTTON_CLASS,
    AUTH_TEXT_LINK_CLASS,
    ButtonSpinner,
} from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { getPendingVerificationEmail, setPendingVerificationEmail } from '@/lib/emailVerification';
import { buildInvitationAuthPath, getPendingInvitationToken } from '@/lib/invitations';
import { getErrorMessage } from '@/lib/utils';

export function VerifyEmailNoticePage() {
    const location = useLocation();
    const [cooldown, setCooldown] = useState(0);
    const [flashSent, setFlashSent] = useState(false);
    const [isSending, setIsSending] = useState(false);

    const inviteToken = location.state?.inviteToken || getPendingInvitationToken();
    const email = useMemo(
        () => location.state?.email || getPendingVerificationEmail(),
        [location.state?.email],
    );

    useEffect(() => {
        document.title = 'Verify email | HVT';
    }, []);

    useEffect(() => {
        if (location.state?.email) {
            setPendingVerificationEmail(location.state.email);
        }
    }, [location.state?.email]);

    useEffect(() => {
        if (cooldown <= 0) return undefined;
        const intervalId = window.setInterval(() => {
            setCooldown((current) => (current > 0 ? current - 1 : 0));
        }, 1000);
        return () => window.clearInterval(intervalId);
    }, [cooldown]);

    useEffect(() => {
        if (!flashSent) return undefined;
        const timeoutId = window.setTimeout(() => setFlashSent(false), 3000);
        return () => window.clearTimeout(timeoutId);
    }, [flashSent]);

    const resendLabel = flashSent
        ? 'Sent!'
        : cooldown > 0
          ? `Resend in ${cooldown}s...`
          : 'Resend verification email';

    const handleResend = async () => {
        if (!email || cooldown > 0) return;
        setIsSending(true);
        try {
            await resendVerificationEmail({ email });
            setPendingVerificationEmail(email);
            setFlashSent(true);
            setCooldown(30);
            toast.success('Verification email sent.');
        } catch (error) {
            toast.error(getErrorMessage(error));
        } finally {
            setIsSending(false);
        }
    };

    return (
        <AuthPageShell>
            <AuthCard>
                <div className="space-y-6 text-center">
                    <Logo align="center" className="mx-auto" />
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a78bfa]">
                        <Mail className="h-7 w-7" />
                    </div>
                    <div className="space-y-2">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Check your email</h1>
                        <p className="text-sm leading-6 text-[#a1a1aa]">
                            We sent a verification link to the address below. Click the link to activate your account.
                        </p>
                    </div>

                    <div className="rounded-full border border-[#27272a] bg-[#18181b] px-4 py-2 font-mono text-sm text-white">
                        {email || 'Email unavailable'}
                    </div>

                    <button
                        type="button"
                        onClick={handleResend}
                        disabled={isSending || cooldown > 0 || !email}
                        className={AUTH_PRIMARY_BUTTON_CLASS}
                    >
                        {isSending ? (
                            <>
                                <ButtonSpinner />
                                Sending...
                            </>
                        ) : flashSent ? (
                            <>
                                <Check className="h-4 w-4" />
                                {resendLabel}
                            </>
                        ) : (
                            resendLabel
                        )}
                    </button>

                    <Link to={buildInvitationAuthPath('/login', inviteToken)} className={AUTH_TEXT_LINK_CLASS}>
                        Wrong email? Sign in with a different account
                    </Link>

                    <p className="text-xs leading-6 text-[#71717a]">Check your spam folder if you don&apos;t see it.</p>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}
