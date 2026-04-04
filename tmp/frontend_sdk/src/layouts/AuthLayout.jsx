import { Outlet } from 'react-router-dom';

import { AuthPageShell } from '@/components/auth/AuthShell';

export function AuthLayout({ children, topLeftLogo = false, topLeftHref = '/', contentClassName = '' }) {
    return (
        <AuthPageShell
            topLeftLogo={topLeftLogo}
            topLeftHref={topLeftHref}
            contentClassName={contentClassName}
        >
            {children ?? <Outlet />}
        </AuthPageShell>
    );
}
