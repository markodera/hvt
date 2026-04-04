import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

import { resendVerificationEmail } from '@/api/auth';
import { AuthCard, AuthPageShell, AUTH_PRIMARY_BUTTON_CLASS, AUTH_TEXT_LINK_CLASS, ButtonSpinner } from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';
import { getPendingVerificationEmail } from '@/lib/emailVerification';
import { getErrorMessage } from '@/lib/utils';

export function VerifyEmailExpiredPage() {
    const navigate = useNavigate();
    const location = useLocation();
    const [isSending, setIsSending] = useState(false);

    const email = useMemo(() => location.state?.email || getPendingVerificationEmail(), [location.state?.email]);
    const message =
        location.state?.message || 'This verification link has expired or already been used. Request a new one.';

    useEffect(() => {
        document.title = 'Verification link expired | HVT';
    }, []);

    const handleRequestNewLink = async () => {
        if (!email) {
            navigate('/verify-email', { replace: true });
            return;
        }

        setIsSending(true);
        try {
            await resendVerificationEmail({ email });
            toast.success('A fresh verification email has been sent.');
            navigate('/verify-email', {
                replace: true,
                state: { email },
            });
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
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#78350f] bg-[#1f1708] text-[#fbbf24]">
                        <AlertTriangle className="h-7 w-7" />
                    </div>
                    <div className="space-y-2">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Link expired</h1>
                        <p className="text-sm leading-6 text-[#a1a1aa]">{message}</p>
                    </div>
                    <button type="button" onClick={handleRequestNewLink} disabled={isSending} className={AUTH_PRIMARY_BUTTON_CLASS}>
                        {isSending ? (
                            <>
                                <ButtonSpinner />
                                Requesting new link...
                            </>
                        ) : (
                            'Request new link'
                        )}
                    </button>
                    <Link to="/login" className={AUTH_TEXT_LINK_CLASS}>
                        Back to sign in
                    </Link>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}
