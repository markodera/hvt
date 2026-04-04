import { useMemo } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
    Grid2x2,
    KeyRound,
    LogOut,
    Moon,
    ScrollText,
    Settings,
    SunMedium,
    User,
    Webhook,
} from 'lucide-react';

import { Logo } from '@/components/Logo';
import { useAuth } from '@/hooks/useAuth';
import { useTheme } from '@/hooks/useTheme';

const navigation = [
    { label: 'Dashboard', to: '/dashboard', icon: Grid2x2 },
    { label: 'Users', to: '/dashboard/users', icon: User },
    { label: 'API Keys', to: '/dashboard/api-keys', icon: KeyRound },
    { label: 'Webhooks', to: '/dashboard/webhooks', icon: Webhook },
    { label: 'Audit Logs', to: '/dashboard/audit-logs', icon: ScrollText },
    { label: 'Settings', to: '/dashboard/settings', icon: Settings },
];

const titleMap = [
    { match: '/dashboard/users', title: 'Users' },
    { match: '/dashboard/api-keys', title: 'API Keys' },
    { match: '/dashboard/webhooks', title: 'Webhooks' },
    { match: '/dashboard/audit-logs', title: 'Audit Logs' },
    { match: '/dashboard/settings', title: 'Settings' },
];

function getInitials(user) {
    const fullName = [user?.first_name, user?.last_name].filter(Boolean).join(' ').trim();
    if (fullName) {
        return fullName
            .split(/\s+/)
            .slice(0, 2)
            .map((part) => part[0]?.toUpperCase())
            .join('');
    }

    return (user?.email || 'HV').slice(0, 2).toUpperCase();
}

function getDisplayName(user) {
    const fullName = [user?.first_name, user?.last_name].filter(Boolean).join(' ').trim();
    return fullName || user?.email || 'HVT user';
}

function resolveTitle(pathname) {
    const matched = titleMap.find((item) => pathname.startsWith(item.match));
    return matched?.title || 'Dashboard';
}

function NavItem({ item, mobile = false }) {
    const Icon = item.icon;
    return (
        <NavLink
            to={item.to}
            end={item.to === '/dashboard'}
            className={({ isActive }) =>
                [
                    'group relative flex items-center gap-3 transition-all duration-150',
                    mobile
                        ? 'min-w-0 flex-1 flex-col justify-center rounded-xl px-2 py-2 text-[11px] font-medium'
                        : 'rounded-lg px-4 py-3 text-sm font-medium',
                    isActive
                        ? 'bg-[#18181b] text-white'
                        : 'text-[#71717a] hover:bg-[#18181b] hover:text-[#a1a1aa]',
                ].join(' ')
            }
        >
            {({ isActive }) => (
                <>
                    {!mobile && isActive ? (
                        <span className="absolute inset-y-2 left-0 w-[3px] rounded-r-full bg-[#7c3aed]" />
                    ) : null}
                    <Icon className="h-4 w-4" />
                    <span className={mobile ? 'truncate' : ''}>{item.label}</span>
                </>
            )}
        </NavLink>
    );
}

export function DashboardShell({ children }) {
    const location = useLocation();
    const { user, logout } = useAuth();
    const { toggleTheme, isDark } = useTheme();
    const pageTitle = useMemo(() => resolveTitle(location.pathname), [location.pathname]);
    const displayName = getDisplayName(user);
    const initials = getInitials(user);

    return (
        <div className="min-h-screen bg-[#0a0a0a] text-white">
            <aside className="fixed inset-y-0 left-0 z-30 hidden w-[220px] border-r border-[#27272a] bg-[#111111] md:flex md:flex-col">
                <div className="border-b border-[#27272a] px-5 py-5">
                    <Logo href="/" />
                </div>

                <nav className="flex-1 space-y-1 px-3 py-4">
                    {navigation.map((item) => (
                        <NavItem key={item.to} item={item} />
                    ))}
                </nav>

                <div className="border-t border-[#27272a] px-4 py-4">
                    <div className="flex items-center gap-3 rounded-xl border border-[#27272a] bg-[#111111] px-3 py-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#7c3aed]/50 bg-[#18181b] text-sm font-semibold text-[#a78bfa]">
                            {initials}
                        </div>
                        <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium text-white">{displayName}</p>
                            <p className="truncate text-xs text-[#71717a]">{user?.email}</p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={logout}
                        className="mt-3 inline-flex items-center gap-2 text-sm font-medium text-[#a1a1aa] transition-colors hover:text-white"
                    >
                        <LogOut className="h-4 w-4" />
                        Sign out
                    </button>
                </div>
            </aside>

            <div className="md:pl-[220px]">
                <header className="sticky top-0 z-20 h-14 border-b border-[#27272a] bg-[#111111]/95 backdrop-blur">
                    <div className="flex h-full items-center justify-between px-4 md:px-6">
                        <h1 className="text-base font-semibold text-white">{pageTitle}</h1>
                        <div className="flex items-center gap-3">
                            <button
                                type="button"
                                onClick={toggleTheme}
                                className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] text-[#a1a1aa] transition-colors hover:border-[#3f3f46] hover:text-white"
                                aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
                            >
                                {isDark ? <SunMedium className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                            </button>
                            <div className="hidden items-center gap-3 rounded-full border border-[#27272a] bg-[#18181b] px-3 py-1.5 md:flex">
                                <div className="flex h-8 w-8 items-center justify-center rounded-full border border-[#7c3aed]/40 bg-[#111111] text-xs font-semibold text-[#a78bfa]">
                                    {initials}
                                </div>
                                <div className="text-left">
                                    <p className="max-w-[180px] truncate text-sm font-medium text-white">{displayName}</p>
                                    <p className="max-w-[180px] truncate text-xs text-[#71717a]">{user?.email}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </header>

                <main className="px-4 py-6 pb-24 md:px-8 md:py-8 md:pb-8">
                    <div className="mx-auto max-w-7xl">{children}</div>
                </main>
            </div>

            <nav className="fixed inset-x-0 bottom-0 z-30 border-t border-[#27272a] bg-[#111111]/95 px-2 py-2 backdrop-blur md:hidden">
                <div className="flex items-center gap-1">
                    {navigation.map((item) => (
                        <NavItem key={item.to} item={item} mobile />
                    ))}
                </div>
            </nav>
        </div>
    );
}
