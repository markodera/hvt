import { Link } from 'react-router-dom';

import { AuthCard, AuthPageShell, AUTH_PRIMARY_BUTTON_CLASS, AUTH_TEXT_LINK_CLASS } from '@/components/auth/AuthShell';

export default function NotFoundPage() {
    return (
        <AuthPageShell topLeftLogo>
            <AuthCard className="max-w-[520px]">
                <div className="space-y-6 text-center">
                    <div className="font-mono text-[80px] font-bold leading-none tracking-[-0.06em] text-[#71717a]">
                        404
                    </div>
                    <div className="space-y-2">
                        <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Page not found</h1>
                        <p className="text-sm leading-6 text-[#a1a1aa]">
                            This page doesn&apos;t exist or you don&apos;t have access to it.
                        </p>
                    </div>
                    <Link to="/" className={AUTH_PRIMARY_BUTTON_CLASS}>
                        Go home
                    </Link>
                    <Link to="/dashboard" className={AUTH_TEXT_LINK_CLASS}>
                        Go to dashboard
                    </Link>
                </div>
            </AuthCard>
        </AuthPageShell>
    );
}

