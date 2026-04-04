import { createBrowserRouter, Navigate, RouterProvider } from 'react-router-dom';

import { ProtectedRoute } from '@/components/ProtectedRoute';
import { AuthLayout } from '@/layouts/AuthLayout';
import { DashboardLayout } from '@/layouts/DashboardLayout';
import Login from '@/pages/auth/Login';
import Signup from '@/pages/auth/Signup';
import { ForgotPasswordPage } from '@/pages/auth/ForgotPasswordPage';
import { ResetPasswordPage } from '@/pages/auth/ResetPasswordPage';
import { ResetPasswordSuccessPage } from '@/pages/auth/ResetPasswordSuccessPage';
import { VerifyEmailNoticePage } from '@/pages/auth/VerifyEmailNoticePage';
import { VerifyEmailSuccessPage } from '@/pages/auth/VerifyEmailSuccessPage';
import { VerifyEmailExpiredPage } from '@/pages/auth/VerifyEmailExpiredPage';
import { VerifyEmailPage } from '@/pages/auth/VerifyEmailPage';
import { GoogleCallbackPage } from '@/pages/auth/GoogleCallbackPage';
import { GitHubCallbackPage } from '@/pages/auth/GitHubCallbackPage';
import { InvitationAcceptPage } from '@/pages/auth/InvitationAcceptPage';
import { AccountLockedPage } from '@/pages/auth/AccountLockedPage';
import DashboardHome from '@/pages/dashboard/DashboardHome';
import UsersPage from '@/pages/users/UsersPage';
import { UserDetailPage } from '@/pages/users/UserDetailPage';
import ApiKeysPage from '@/pages/api-keys/ApiKeysPage';
import WebhooksPage from '@/pages/webhooks/WebhooksPage';
import { WebhookDetailPage } from '@/pages/webhooks/WebhookDetailPage';
import AuditLogsPage from '@/pages/audit/AuditLogsPage';
import SettingsPage from '@/pages/settings/SettingsPage';
import { CreateOrganizationPage } from '@/pages/settings/CreateOrganizationPage';
import Landing from '@/pages/landing/Landing';
import NotFoundPage from '@/pages/NotFoundPage';

const router = createBrowserRouter([
    { path: '/', element: <Landing /> },
    { path: '/login', element: <Login /> },
    { path: '/signup', element: <Signup /> },
    { path: '/register', element: <Navigate to="/signup" replace /> },
    { path: '/forgot-password', element: <ForgotPasswordPage /> },
    { path: '/reset-password', element: <ResetPasswordPage /> },
    { path: '/reset-password/success', element: <ResetPasswordSuccessPage /> },
    { path: '/password/reset/confirm/:uid/:token', element: <ResetPasswordPage /> },
    { path: '/auth/password-reset/:key', element: <Navigate to="/forgot-password" replace /> },
    { path: '/verify-email', element: <VerifyEmailNoticePage /> },
    { path: '/verify-email/success', element: <VerifyEmailSuccessPage /> },
    { path: '/verify-email/expired', element: <VerifyEmailExpiredPage /> },
    { path: '/auth/verify-email-notice', element: <VerifyEmailNoticePage /> },
    { path: '/auth/verify-email/:key', element: <VerifyEmailPage /> },
    { path: '/invite', element: <InvitationAcceptPage /> },
    { path: '/invite/accept', element: <InvitationAcceptPage /> },
    { path: '/account-locked', element: <AccountLockedPage /> },
    { path: '/auth/google/callback', element: <GoogleCallbackPage /> },
    { path: '/auth/github/callback', element: <GitHubCallbackPage /> },
    {
        element: (
            <ProtectedRoute>
                <AuthLayout />
            </ProtectedRoute>
        ),
        children: [{ path: '/dashboard/create-organization', element: <CreateOrganizationPage /> }],
    },
    {
        element: (
            <ProtectedRoute>
                <DashboardLayout />
            </ProtectedRoute>
        ),
        children: [
            { path: '/dashboard', element: <DashboardHome /> },
            { path: '/dashboard/users', element: <UsersPage /> },
            { path: '/dashboard/users/:id', element: <UserDetailPage /> },
            { path: '/dashboard/api-keys', element: <ApiKeysPage /> },
            { path: '/dashboard/webhooks', element: <WebhooksPage /> },
            { path: '/dashboard/webhooks/:id', element: <WebhookDetailPage /> },
            { path: '/dashboard/audit-logs', element: <AuditLogsPage /> },
            { path: '/dashboard/settings', element: <SettingsPage /> },
        ],
    },
    { path: '*', element: <NotFoundPage /> },
]);

export function App() {
    return <RouterProvider router={router} />;
}

export default App;
