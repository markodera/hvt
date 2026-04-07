import { createBrowserRouter, Navigate, RouterProvider, useLocation } from 'react-router-dom';

import { ProtectedRoute } from '@/components/ProtectedRoute';
import { DashboardLayout } from '@/layouts/DashboardLayout';

import Landing from '@/pages/landing/Landing';
import Login from '@/pages/auth/Login';
import Signup from '@/pages/auth/Signup';
import { ForgotPasswordPage } from '@/pages/auth/ForgotPasswordPage';
import { ResetPasswordPage } from '@/pages/auth/ResetPasswordPage';
import { VerifyEmailExpiredPage } from '@/pages/auth/VerifyEmailExpiredPage';
import { VerifyEmailNoticePage } from '@/pages/auth/VerifyEmailNoticePage';
import { VerifyEmailPage } from '@/pages/auth/VerifyEmailPage';
import { VerifyEmailSuccessPage } from '@/pages/auth/VerifyEmailSuccessPage';
import { GoogleCallbackPage } from '@/pages/auth/GoogleCallbackPage';
import { GitHubCallbackPage } from '@/pages/auth/GitHubCallbackPage';
import { InvitePage } from '@/pages/auth/InvitePage';
import DashboardHome from '@/pages/dashboard/DashboardHome';
import UsersPage from '@/pages/users/UsersPage';
import PrivacyPolicyPage from '@/pages/legal/PrivacyPolicyPage';
import TermsOfServicePage from '@/pages/legal/TermsOfServicePage';
import { UserDetailPage } from '@/pages/users/UserDetailPage';
import ApiKeysPage from '@/pages/api-keys/ApiKeysPage';
import WebhooksPage from '@/pages/webhooks/WebhooksPage';
import { WebhookDetailPage } from '@/pages/webhooks/WebhookDetailPage';
import AuditLogsPage from '@/pages/audit/AuditLogsPage';
import SettingsPage from '@/pages/settings/SettingsPage';
import { CreateOrganizationPage } from '@/pages/settings/CreateOrganizationPage';
import NotFoundPage from '@/pages/NotFoundPage';
import RuntimePlaygroundPage from '@/pages/runtime/RuntimePlaygroundPage';

function InviteAcceptRedirect() {
    const location = useLocation();
    return <Navigate to={`/invite${location.search || ''}`} replace />;
}

const router = createBrowserRouter([
    { path: '/', element: <Landing /> },
    { path: '/login', element: <Login /> },
    { path: '/signup', element: <Signup /> },
    { path: '/register', element: <Navigate to="/signup" replace /> },
    { path: '/privacy-policy', element: <PrivacyPolicyPage /> },
    { path: '/terms-of-service', element: <TermsOfServicePage /> },
    { path: '/verify-email', element: <VerifyEmailNoticePage /> },
    { path: '/verify-email/expired', element: <VerifyEmailExpiredPage /> },
    { path: '/verify-email/success', element: <VerifyEmailSuccessPage /> },
    { path: '/verify-email/:key', element: <VerifyEmailPage /> },
    { path: '/auth/verify-email-notice', element: <VerifyEmailNoticePage /> },
    { path: '/forgot-password', element: <ForgotPasswordPage /> },
    { path: '/reset-password/:uid/:token', element: <ResetPasswordPage /> },
    { path: '/reset-password/:key', element: <ResetPasswordPage /> },
    { path: '/auth/password-reset/:uid/:token', element: <ResetPasswordPage /> },
    { path: '/auth/password-reset/:key', element: <ResetPasswordPage /> },
    { path: '/invite', element: <InvitePage /> },
    { path: '/invite/accept', element: <InviteAcceptRedirect /> },
    { path: '/auth/verify-email/:key', element: <VerifyEmailPage /> },
    { path: '/auth/google/callback', element: <GoogleCallbackPage /> },
    { path: '/auth/github/callback', element: <GitHubCallbackPage /> },
    { path: '/runtime-playground', element: <RuntimePlaygroundPage /> },
    { path: '/runtime-playground/callback/:provider', element: <RuntimePlaygroundPage /> },
    {
        element: (
            <ProtectedRoute>
                <DashboardLayout />
            </ProtectedRoute>
        ),
        children: [
            { path: '/dashboard', element: <DashboardHome /> },
            { path: '/dashboard/create-organization', element: <CreateOrganizationPage /> },
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
