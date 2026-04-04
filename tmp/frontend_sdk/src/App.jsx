import { createBrowserRouter, Navigate, RouterProvider, useLocation } from 'react-router-dom';

import { ProtectedRoute } from '@/components/ProtectedRoute';
import { DashboardLayout } from '@/layouts/DashboardLayout';

import Landing from '@/pages/landing/Landing';
import Login from '@/pages/auth/Login';
import Signup from '@/pages/auth/Signup';
import { ForgotPasswordPage } from '@/pages/auth/ForgotPasswordPage';
import { ResetPasswordPage } from '@/pages/auth/ResetPasswordPage';
import { VerifyEmailNoticePage } from '@/pages/auth/VerifyEmailNoticePage';
import { VerifyEmailPage } from '@/pages/auth/VerifyEmailPage';
import { GoogleCallbackPage } from '@/pages/auth/GoogleCallbackPage';
import { GitHubCallbackPage } from '@/pages/auth/GitHubCallbackPage';
import { InvitePage } from '@/pages/auth/InvitePage';
import DashboardHome from '@/pages/dashboard/DashboardHome';
import UsersPage from '@/pages/users/UsersPage';
import { UserDetailPage } from '@/pages/users/UserDetailPage';
import ApiKeysPage from '@/pages/api-keys/ApiKeysPage';
import WebhooksPage from '@/pages/webhooks/WebhooksPage';
import { WebhookDetailPage } from '@/pages/webhooks/WebhookDetailPage';
import AuditLogsPage from '@/pages/audit/AuditLogsPage';
import SettingsPage from '@/pages/settings/SettingsPage';

function InviteAcceptRedirect() {
    const location = useLocation();
    return <Navigate to={`/invite${location.search || ''}`} replace />;
}

const router = createBrowserRouter([
    { path: '/', element: <Landing /> },
    { path: '/login', element: <Login /> },
    { path: '/signup', element: <Signup /> },
    { path: '/register', element: <Navigate to="/signup" replace /> },
    { path: '/auth/verify-email-notice', element: <VerifyEmailNoticePage /> },
    { path: '/forgot-password', element: <ForgotPasswordPage /> },
    { path: '/auth/password-reset/:uid/:token', element: <ResetPasswordPage /> },
    { path: '/auth/password-reset/:key', element: <ResetPasswordPage /> },
    { path: '/invite', element: <InvitePage /> },
    { path: '/invite/accept', element: <InviteAcceptRedirect /> },
    { path: '/auth/verify-email/:key', element: <VerifyEmailPage /> },
    { path: '/auth/google/callback', element: <GoogleCallbackPage /> },
    { path: '/auth/github/callback', element: <GitHubCallbackPage /> },
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
    { path: '*', element: <Navigate to="/" replace /> },
]);

export function App() {
    return <RouterProvider router={router} />;
}

export default App;
