import { Outlet, Link } from 'react-router-dom';
import { useState } from 'react';
import { Menu, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Logo } from '@/components/Logo';

function NavLink({ to, children, onClick }) {
    return (
        <Link
            to={to}
            onClick={onClick}
            className="text-sm font-medium text-text-secondary transition-colors hover:text-text-primary"
        >
            {children}
        </Link>
    );
}

function LandingNav() {
    const [mobileOpen, setMobileOpen] = useState(false);

    return (
        <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-bg-primary/80 backdrop-blur-xl">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex h-16 items-center justify-between">
                    <Logo href="/" />

                    <div className="hidden md:flex items-center gap-8 rounded-full border border-border bg-bg-secondary/60 px-6 py-2">
                        <NavLink to="/#why-hvt">Why HVT</NavLink>
                        <NavLink to="/#system">System model</NavLink>
                        <NavLink to="/#features">Features</NavLink>
                        <NavLink to="/#integration">Integration</NavLink>
                        <a
                            href="https://github.com"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sm font-medium text-text-secondary transition-colors hover:text-text-primary"
                        >
                            GitHub
                        </a>
                    </div>

                    <div className="hidden md:flex items-center gap-3">
                        <Button variant="ghost" asChild className="font-semibold text-text-secondary hover:text-text-primary">
                            <Link to="/login">Sign in</Link>
                        </Button>
                        <Button asChild className="font-semibold shadow-lg shadow-primary/20 transition-shadow hover:shadow-primary/40">
                            <Link to="/register">Get started</Link>
                        </Button>
                    </div>

                    <button
                        className="rounded-lg p-2 text-text-primary transition-colors hover:bg-bg-secondary md:hidden"
                        onClick={() => setMobileOpen(!mobileOpen)}
                        aria-label="Toggle menu"
                    >
                        {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
                    </button>
                </div>

                {mobileOpen && (
                    <div className="space-y-4 border-t border-border py-4 md:hidden">
                        <NavLink to="/#why-hvt" onClick={() => setMobileOpen(false)}>Why HVT</NavLink>
                        <NavLink to="/#system" onClick={() => setMobileOpen(false)}>System model</NavLink>
                        <NavLink to="/#features" onClick={() => setMobileOpen(false)}>Features</NavLink>
                        <NavLink to="/#integration" onClick={() => setMobileOpen(false)}>Integration</NavLink>
                        <div className="flex flex-col gap-2 pt-2">
                            <Button variant="outline" asChild className="w-full">
                                <Link to="/login">Sign in</Link>
                            </Button>
                            <Button asChild className="w-full">
                                <Link to="/register">Get started</Link>
                            </Button>
                        </div>
                    </div>
                )}
            </div>
        </nav>
    );
}

function LandingFooter() {
    return (
        <footer className="border-t border-border bg-bg-secondary">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
                <div className="grid gap-10 md:grid-cols-[1.2fr_1fr_1fr]">
                    <div>
                        <div className="flex items-center gap-3">
                            <Logo href="/" />
                            <p className="text-sm text-text-secondary">Open-source auth infrastructure for modern product teams.</p>
                        </div>
                    </div>

                    <div>
                        <h4 className="mb-4 text-xs font-semibold uppercase tracking-[0.24em] text-text-secondary">Explore</h4>
                        <ul className="space-y-2">
                            <li><a href="/#why-hvt" className="text-sm text-text-muted transition-colors hover:text-text-primary">Why HVT</a></li>
                            <li><a href="/#system" className="text-sm text-text-muted transition-colors hover:text-text-primary">System model</a></li>
                            <li><a href="/#integration" className="text-sm text-text-muted transition-colors hover:text-text-primary">Integration</a></li>
                        </ul>
                    </div>

                    <div>
                        <h4 className="mb-4 text-xs font-semibold uppercase tracking-[0.24em] text-text-secondary">Start</h4>
                        <ul className="space-y-2">
                            <li><Link to="/register" className="text-sm text-text-muted transition-colors hover:text-text-primary">Create account</Link></li>
                            <li><Link to="/login" className="text-sm text-text-muted transition-colors hover:text-text-primary">Sign in</Link></li>
                            <li><a href="https://github.com" target="_blank" rel="noopener noreferrer" className="text-sm text-text-muted transition-colors hover:text-text-primary">GitHub</a></li>
                        </ul>
                    </div>
                </div>

                <div className="mt-10 border-t border-border pt-8 text-center">
                    <p className="text-sm text-text-muted">Copyright {new Date().getFullYear()} HVT. AGPL v3 licensed.</p>
                </div>
            </div>
        </footer>
    );
}

export function LandingLayout() {
    return (
        <div className="min-h-screen bg-bg-primary">
            <LandingNav />
            <main className="pt-16">
                <Outlet />
            </main>
            <LandingFooter />
        </div>
    );
}
