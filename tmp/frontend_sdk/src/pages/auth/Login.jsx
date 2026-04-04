import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Eye, EyeOff, Github } from 'lucide-react';
import { z } from 'zod';

import { listSocialProviders } from '@/api/auth';
import { Logo } from '@/components/Logo';
import { useAuth } from '@/hooks/useAuth';
import { SOCIAL_AUTH_PROVIDERS, startSocialSignIn } from '@/lib/socialAuth';
import {
  buildInvitationAcceptPath,
  consumeInvitationResumeToken,
  markInvitationResumeAfterAuth,
} from '@/lib/invitations';
import { getErrorMessage } from '@/lib/utils';

const DOT_GRID_STYLE = {
  backgroundImage:
    'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
  backgroundRepeat: 'repeat',
};

const loginSchema = z.object({
  email: z.string().email('Enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
});

function GoogleIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

function AuthBackground() {
  return (
    <>
      <style>{`
        @keyframes authGlowPulse {
          0%, 100% { opacity: 0.18; }
          50% { opacity: 0.34; }
        }
      `}</style>
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
            'linear-gradient(to bottom, rgba(0,0,0,0.92) 0%, rgba(0,0,0,0.88) 68%, transparent 100%)',
          maskImage:
            'linear-gradient(to bottom, rgba(0,0,0,0.92) 0%, rgba(0,0,0,0.88) 68%, transparent 100%)',
        }}
      />
    </>
  );
}

function Wordmark({ centered = false }) {
  return <Logo href="/" align={centered ? 'center' : 'left'} className={centered ? 'mx-auto' : ''} />;
}

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [showPassword, setShowPassword] = useState(false);
  const inviteToken = searchParams.get('invite_token') || '';

  useEffect(() => {
    document.title = 'Login | HVT';
  }, []);

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

  const handleSocialLogin = (provider, label) => {
    if (inviteToken) {
      markInvitationResumeAfterAuth(inviteToken);
    }
    const started = startSocialSignIn(provider, controlPlaneProviders);
    if (!started) {
      toast.error(`${label} login is not configured`);
    }
  };

  const onSubmit = async (values) => {
    try {
      await login(values);
      const resumeInvitationToken = consumeInvitationResumeToken();
      toast.success('Signed in');
      if (resumeInvitationToken) {
        navigate(buildInvitationAcceptPath(resumeInvitationToken));
        return;
      }
      navigate('/dashboard');
    } catch (error) {
      toast.error(getErrorMessage(error));
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-white">
      <AuthBackground />

      <div className="relative flex min-h-screen items-center justify-center px-4 py-10 sm:px-6">
        <div className="w-full max-w-[440px] rounded-[20px] border border-[#27272a] bg-[#111111]/92 p-8 shadow-[0_0_0_1px_rgba(124,58,237,0.06)] backdrop-blur-sm transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] sm:p-10">
          <div className="flex justify-center">
            <Wordmark centered />
          </div>

          <div className="mt-8 text-center">
            <h1 className="text-3xl font-bold tracking-[-0.03em] text-white">Sign in</h1>
            <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
              Access your organization control plane and runtime settings.
            </p>
          </div>

          <div className="mt-8 space-y-3">
            <button
              type="button"
              onClick={() => handleSocialLogin(SOCIAL_AUTH_PROVIDERS.GOOGLE, 'Google')}
              disabled={!googleAvailable}
              className="flex w-full items-center justify-center gap-3 rounded-md border border-[#27272a] bg-transparent px-4 py-3 text-sm font-medium text-[#e4e4e7] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              <GoogleIcon />
              Continue with Google
            </button>
            <button
              type="button"
              onClick={() => handleSocialLogin(SOCIAL_AUTH_PROVIDERS.GITHUB, 'GitHub')}
              disabled={!githubAvailable}
              className="flex w-full items-center justify-center gap-3 rounded-md border border-[#27272a] bg-transparent px-4 py-3 text-sm font-medium text-[#e4e4e7] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Github className="h-4 w-4" />
              Continue with GitHub
            </button>
          </div>

          <div className="relative my-8">
            <div className="h-px w-full bg-[#27272a]" />
            <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#111111] px-3 text-xs uppercase tracking-[0.14em] text-[#71717a]">
              or continue with email
            </span>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium text-white">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                {...register('email')}
                className="w-full rounded-md border border-[#27272a] bg-[#0a0a0a] px-4 py-3 text-sm text-white outline-none transition-colors duration-150 placeholder:text-[#52525b] focus:border-[#7c3aed]"
              />
              {errors.email ? <p className="text-xs text-[#f87171]">{errors.email.message}</p> : null}
            </div>

            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium text-white">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="Enter your password"
                  {...register('password')}
                  className="w-full rounded-md border border-[#27272a] bg-[#0a0a0a] px-4 py-3 pr-11 text-sm text-white outline-none transition-colors duration-150 placeholder:text-[#52525b] focus:border-[#7c3aed]"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#71717a] transition-colors hover:text-white"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password ? <p className="text-xs text-[#f87171]">{errors.password.message}</p> : null}
              <div className="flex justify-end">
                <Link to="/forgot-password" className="text-xs text-[#71717a] transition-colors hover:text-[#a78bfa]">
                  Forgot password?
                </Link>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full rounded-md bg-[#7c3aed] px-4 py-3 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#6d28d9] disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isSubmitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-center text-sm text-[#a1a1aa]">
            Don't have an account?{' '}
            <Link to="/signup" className="font-medium text-[#a78bfa] transition-colors hover:text-white">
              Get started free
            </Link>
          </p>

          {controlPlaneProviders.length === 0 ? (
            <p className="mt-4 text-center text-xs text-[#71717a]">
              Social sign-in is not configured for this environment yet.
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
