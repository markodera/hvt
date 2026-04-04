import { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Lock } from 'lucide-react';

import { AuthCard, AuthPageShell, AUTH_PRIMARY_BUTTON_CLASS, AUTH_TEXT_LINK_CLASS } from '@/components/auth/AuthShell';
import { Logo } from '@/components/Logo';

export function AccountLockedPage() {
    const location = useLocation();
    const minutes = location.state?.minutes;
    const message =
        location.state?.detail ||
        (minutes
            ? `Too many failed attempts. Try again in ${minutes} minutes or reset your password.`
            : 'Too many failed attempts. Try again later or reset your password.');

    useEffect(() => {
        document.title = 'Account temporarily locked | HVT';
    }, []);

    return (
        <AuthPageShell>
            <AuthCard>
                <div className="space-y-6 text-center">
                    <Logo align="center" className="mx-auto" />
                    <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-[#7f1d1d] bg-[#1f1416] text-[#f87171]">
                        <Lock className="h-7 w-7" />
                    </div>
                    <div className="space-y-2">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Account temporarily locked</h1>
                        <p className="text-sm leading-6 text-[#a1a1aa]">{message}</p>
                    </div>
                    <Link to="/forgot-password" className={AUTH_PRIMARY_BUTTON_CLASS}>
                        Reset password
                    </Link>
                    <Link to="/login" className={AUTH_TEXT_LINK_CLASS}>
                        Back to sign in
                    </Link>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}

