import { Loader2 } from 'lucide-react';

import { Logo } from '@/components/Logo';
import { cn } from '@/lib/utils';

const DOT_GRID_STYLE = {
    backgroundImage:
        'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
    backgroundRepeat: 'repeat',
};

export const AUTH_INPUT_CLASS =
    'h-10 w-full rounded-lg border border-[#27272a] bg-[#18181b] px-3 text-sm text-white outline-none transition-[border-color,box-shadow,background-color] duration-150 placeholder:text-[#71717a] focus:border-[#7c3aed]/60 focus:shadow-[0_0_0_2px_rgba(124,58,237,0.25)]';

export const AUTH_PRIMARY_BUTTON_CLASS =
    'inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-[#7c3aed] px-4 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#6d28d9] disabled:cursor-not-allowed disabled:opacity-60';

export const AUTH_GHOST_BUTTON_CLASS =
    'inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-[#27272a] bg-transparent px-4 text-sm font-semibold text-white transition-colors duration-150 hover:border-[#3f3f46] hover:bg-[#18181b] disabled:cursor-not-allowed disabled:opacity-60';

export const AUTH_TEXT_LINK_CLASS =
    'text-sm text-[#a1a1aa] transition-colors duration-150 hover:text-white';

export function ButtonSpinner({ className = '' }) {
    return <Loader2 className={cn('h-4 w-4 animate-spin', className)} aria-hidden="true" />;
}

export function AuthPageShell({ children, topLeftLogo = false, topLeftHref = '/', contentClassName = '' }) {
    return (
        <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] px-4 py-8 text-white sm:px-6">
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
                style={{
                    background:
                        'radial-gradient(circle at top center, rgba(124,58,237,0.15), transparent 56%)',
                }}
            />
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
                style={{
                    ...DOT_GRID_STYLE,
                    WebkitMaskImage:
                        'linear-gradient(to bottom, rgba(0,0,0,0.94) 0%, rgba(0,0,0,0.88) 65%, transparent 100%)',
                    maskImage:
                        'linear-gradient(to bottom, rgba(0,0,0,0.94) 0%, rgba(0,0,0,0.88) 65%, transparent 100%)',
                }}
            />

            {topLeftLogo ? (
                <div className="relative z-10 mx-auto flex max-w-7xl justify-start">
                    <Logo href={topLeftHref} className="mt-1" />
                </div>
            ) : null}

            <div
                className={cn(
                    'relative z-10 flex min-h-[calc(100vh-4rem)] items-center justify-center',
                    contentClassName,
                )}
            >
                {children}
            </div>
        </div>
    );
}

export function AuthCard({ children, className = '' }) {
    return (
        <div
            className={cn(
                'w-full max-w-[480px] rounded-[22px] border border-[#27272a] bg-[#111111]/92 p-6 shadow-[0_32px_80px_rgba(0,0,0,0.45)] backdrop-blur sm:p-8',
                className,
            )}
        >
            {children}
        </div>
    );
}

export function AuthCardHeader({ title, subtitle, children }) {
    return (
        <div className="space-y-4 text-center">
            <Logo align="center" className="mx-auto" />
            {children}
            <div className="space-y-2">
                <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">{title}</h1>
                {subtitle ? <p className="text-sm leading-6 text-[#a1a1aa]">{subtitle}</p> : null}
            </div>
        </div>
    );
}

export function AuthDivider({ label = 'or continue with email' }) {
    return (
        <div className="flex items-center gap-3 text-xs uppercase tracking-[0.18em] text-[#71717a]">
            <div className="h-px flex-1 bg-[#27272a]" />
            <span>{label}</span>
            <div className="h-px flex-1 bg-[#27272a]" />
        </div>
    );
}

export function AuthStatusPill({ children }) {
    return (
        <div className="inline-flex items-center justify-center rounded-full border border-[#27272a] bg-[#18181b] px-3 py-1 text-xs font-medium text-[#e4e4e7]">
            {children}
        </div>
    );
}

export function AuthFieldError({ children }) {
    if (!children) return null;
    return <p className="text-xs text-[#f87171]">{children}</p>;
}

