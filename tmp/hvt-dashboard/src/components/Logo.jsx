import { useId } from 'react';
import { Link } from 'react-router-dom';

import { cn } from '@/lib/utils';

export function HvtLogoMark({ className = '' }) {
    const maskId = useId();

    return (
        <svg
            className={className}
            width="32"
            height="32"
            viewBox="0 0 32 32"
            fill="none"
            aria-hidden="true"
        >
            <defs>
                <mask id={maskId}>
                    <rect width="32" height="32" rx="7" fill="white" />
                    <rect x="8" y="5" width="5" height="22" rx="1.5" fill="black" />
                    <rect x="19" y="5" width="5" height="22" rx="1.5" fill="black" />
                    <rect x="8" y="13" width="16" height="7" rx="1" fill="black" />
                    <rect x="13" y="13" width="6" height="7" fill="white" />
                </mask>
            </defs>
            <rect width="32" height="32" rx="7" fill="#5b21b6" mask={`url(#${maskId})`} />
        </svg>
    );
}

export function Logo({
    href = '/',
    className = '',
    showDomain = true,
    align = 'left',
    labelClassName = '',
}) {
    const alignmentClass = align === 'center' ? 'justify-center text-center' : 'justify-start text-left';

    return (
        <Link to={href} className={cn('inline-flex items-center gap-3', alignmentClass, className)}>
            <HvtLogoMark className="h-8 w-8 shrink-0" />
            <div className={cn('space-y-0.5', labelClassName)}>
                <div className="font-mono text-[1.0625rem] font-bold tracking-[-0.3px] text-white">HVT</div>
                {showDomain ? <div className="text-[11px] text-[#71717a]">hvts.app</div> : null}
            </div>
        </Link>
    );
}

