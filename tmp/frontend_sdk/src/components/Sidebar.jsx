import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import {
    LayoutDashboard,
    Users,
    Key,
    Webhook,
    ScrollText,
    Settings,
    LogOut,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { NAV_ITEMS } from '@/lib/constants';
import { Logo } from '@/components/Logo';

const iconMap = {
    LayoutDashboard,
    Users,
    Key,
    Webhook,
    ScrollText,
    Settings,
};

export function Sidebar() {
    const { user, logout } = useAuth();
    const location = useLocation();

    const filteredItems = NAV_ITEMS.filter((item) => {
        if (!item.roles) return true;
        return user && item.roles.includes(user.role);
    });

    return (
        <aside className="fixed left-0 top-0 bottom-0 w-[240px] bg-sidebar border-r border-border flex flex-col z-40">
            {/* Logo */}
            <div className="h-16 flex items-center px-6 border-b border-border/50">
                <Logo href="/" />
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
                {filteredItems.map((item) => {
                    const Icon = iconMap[item.icon];
                    const isActive =
                        item.path === '/dashboard'
                            ? location.pathname === '/dashboard'
                            : location.pathname.startsWith(item.path);

                    return (
                        <NavLink
                            key={item.path}
                            to={item.path}
                            className={cn(
                                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                                isActive
                                    ? 'bg-primary/10 text-primary'
                                    : 'text-gray-400 hover:bg-white/5 hover:text-white'
                            )}
                        >
                            {Icon && <Icon className="h-4 w-4 shrink-0" />}
                            {item.label}
                        </NavLink>
                    );
                })}
            </nav>

            {/* User info */}
            {user && (
                <div className="px-3 py-4 border-t border-border/50">
                    <div className="flex items-center gap-3 px-3 py-2">
                        <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-sm font-semibold text-primary shrink-0">
                            {user.first_name?.[0]}{user.last_name?.[0]}
                        </div>
                        <div className="min-w-0 flex-1">
                            <p className="text-sm font-medium text-white truncate">
                                {user.full_name || user.email}
                            </p>
                            <p className="text-xs text-gray-500 truncate">{user.email}</p>
                        </div>
                    </div>
                    <button
                        onClick={logout}
                        className="flex items-center gap-3 w-full px-3 py-2 mt-1 rounded-lg text-sm text-gray-400 hover:bg-white/5 hover:text-white transition-colors"
                    >
                        <LogOut className="h-4 w-4" />
                        Sign out
                    </button>
                </div>
            )}
        </aside>
    );
}
