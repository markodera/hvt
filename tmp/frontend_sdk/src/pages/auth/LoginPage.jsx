import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Eye, EyeOff, Github } from 'lucide-react';

import { listSocialProviders } from '@/api/auth';
import { useAuth } from '@/hooks/useAuth';
import { loginSchema } from '@/lib/schemas';
import { SOCIAL_AUTH_PROVIDERS, startSocialSignIn } from '@/lib/socialAuth';
import { buildInvitationAcceptPath, consumeInvitationResumeToken, markInvitationResumeAfterAuth } from '@/lib/invitations';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { getErrorMessage } from '@/lib/utils';

export function LoginPage() {
    const { login } = useAuth();
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const [showPassword, setShowPassword] = useState(false);
    const inviteToken = searchParams.get('invite_token') || '';

    useEffect(() => {
        if (inviteToken) {
            markInvitationResumeAfterAuth(inviteToken);
        }
    }, [inviteToken]);

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting },
    } = useForm({
        resolver: zodResolver(loginSchema),
        defaultValues: { email: '', password: '' },
    });

    const { data: socialProviderData } = useQuery({
        queryKey: ['controlPlaneSocialProviders'],
        queryFn: listSocialProviders,
    });

    const controlPlaneProviders = socialProviderData?.providers ?? [];
    const googleAvailable = controlPlaneProviders.some((provider) => provider.provider === 'google');
    const githubAvailable = controlPlaneProviders.some((provider) => provider.provider === 'github');

    const onSubmit = async (data) => {
        try {
            await login(data);
            const resumeInvitationToken = consumeInvitationResumeToken();
            toast.success('Welcome back!');
            if (resumeInvitationToken) {
                navigate(buildInvitationAcceptPath(resumeInvitationToken));
                return;
            }
            navigate('/dashboard');
        } catch (err) {
            toast.error(getErrorMessage(err));
        }
    };

    const handleSocialLogin = (provider, label) => {
        if (inviteToken) {
            markInvitationResumeAfterAuth(inviteToken);
        }
        const started = startSocialSignIn(provider, controlPlaneProviders);
        if (!started) {
            toast.error(`${label} login is not configured`);
        }
    };

    return (
        <div>
            <div className="mb-6 text-center">
                <h2 className="text-2xl font-extrabold text-text-primary">Welcome back</h2>
                <p className="mt-1 text-sm text-text-secondary">Sign in to your account</p>
            </div>

            <div className="space-y-3">
                <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => handleSocialLogin(SOCIAL_AUTH_PROVIDERS.GOOGLE, 'Google')}
                    type="button"
                    disabled={!googleAvailable}
                >
                    <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                    </svg>
                    Google
                </Button>
                <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => handleSocialLogin(SOCIAL_AUTH_PROVIDERS.GITHUB, 'GitHub')}
                    type="button"
                    disabled={!githubAvailable}
                >
                    <Github className="mr-2 h-4 w-4" />
                    GitHub
                </Button>
            </div>

            {controlPlaneProviders.length === 0 && (
                <p className="mt-3 text-center text-xs text-text-secondary">
                    Social sign-in is not configured for this environment yet.
                </p>
            )}

            <div className="relative my-6">
                <Separator />
                <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-bg-secondary px-3 text-xs text-text-muted">
                    or continue with email
                </span>
            </div>

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input id="email" type="email" placeholder="you@example.com" {...register('email')} />
                    {errors.email && <p className="text-xs text-danger">{errors.email.message}</p>}
                </div>

                <div className="space-y-2">
                    <div className="flex items-center justify-between">
                        <Label htmlFor="password">Password</Label>
                        <Link to="/forgot-password" className="text-xs text-primary transition-colors hover:text-primary-hover">
                            Forgot password?
                        </Link>
                    </div>
                    <div className="relative">
                        <Input
                            id="password"
                            type={showPassword ? 'text' : 'password'}
                            placeholder="••••••••"
                            {...register('password')}
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted transition-colors hover:text-text-primary"
                            aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                            {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                    </div>
                    {errors.password && <p className="text-xs text-danger">{errors.password.message}</p>}
                </div>

                <Button type="submit" className="w-full" disabled={isSubmitting}>
                    {isSubmitting ? 'Signing in...' : 'Sign in'}
                </Button>
            </form>

            <p className="mt-6 text-center text-sm text-text-secondary">
                Don't have an account?{' '}
                <Link to="/signup" className="font-medium text-primary transition-colors hover:text-primary-hover">
                    Get started free
                </Link>
            </p>
        </div>
    );
}

export default LoginPage;
