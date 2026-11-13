# HVT Dashboard Frontend Redesign & Design System Overhaul

* **Author:** Mark Odera
* **Date:** 2026-11-08
* **Status:** Synthesized Goldfish Brief (Post-Swarm Review)

---

## 1. Overview

The HVT control-plane frontend (`hvt-fr`) is undergoing a complete architectural and visual redesign. The overhaul eliminates legacy structural bottlenecks (an 858-line monolithic settings page, unvirtualized 15,000px DOM heights, 11 backend features with zero UI representation, and client-side record truncation) and purges all AI-generated design hallmarks (micro-tracking eyebrows, pulsing dots, sparkle hype icons, and cramped card meshes).

The target standard blends **Stripe's authoritative technical clarity** (keys, test/live state, webhooks, audit logs) with **Supabase's navigational ergonomics** (collapsible left sidebar plus spacious data tables), executed in HVT's original deep-space violet palette (`#000000`, `#0A0A0F`, `#12111A`, `#7C3AED`).

---

## 2. Core Architecture & Navigation

### Global Header Shell
* **Breadcrumbs & Switcher:** `[Organization] / [Project]` dropdowns for tenant navigation, featuring a prominent, copyable Project ID badge (`HVT_PROJECT_ID`) right beside the project name so developers never have to dig into settings to find it.
* **Environment Switcher:** Segmented control toggling `Test` and `Live`.
  * In `Test` mode: Displays a persistent notification strip and an explicit `"TEST MODE"` text badge with `role="switch"` and `aria-checked="true/false"` (ensuring accessibility without relying on color alone).
* **User Profile & Account Menu:** Top-right anchored profile, theme toggle, and personal settings shortcut.
* **Persistent Project State (`ProjectContext`):** Active project slug and ID are managed via a centralized `ProjectContext` synchronized with URL route parameters (`/dashboard/p/:projectSlug/...` or `?project=:slug`) and stored in `localStorage` as fallback, preventing project context loss on page navigation.

### Left Sidebar Navigation (Project-Scoped)
Organized into clean, spacious sections:
1. **Overview:** Project dashboard, onboarding checklist, and machine-readable setup prompt.
2. **Access Control:** Roles & Permissions (matrix grid view + side drawer editor).
3. **Authentication:** Auth Methods (Passwords, Passkeys, TOTP, Magic Links), Social Providers, and Email Providers (BYO SMTP/SES/Resend).
4. **Developers:** API Keys (dual-plane runtime vs. management keys), Webhooks & Deliveries, and Audit Logs.
5. **Runtime Users:** Project end-users and pending runtime invitations.
6. **Project Settings:** Project metadata, domain origins, and workspace configuration.

### Environment Scoping & Badge Invariant (Goldfish Verified)
* **API Keys:** Scoped by `environment` (`test` vs. `live`) `[VERIFIED hvt/apps/organizations/models.py:528]`.
* **Runtime Users:** Scoped by `User.is_test` `[VERIFIED hvt/apps/users/models.py:75]`. When in `Test` mode, Runtime Users queries pass `?is_test=true`; when in `Live` mode, queries pass `?is_test=false`, preventing test sandbox users from polluting production registries.
* **Project-Wide Entities:** Roles, Permissions, Providers, Email Config, Webhooks, and Platform Members are project-wide `[VERIFIED hvt/apps/organizations/models.py]`.
* **UI Invariant:** All project-wide pages display a clear `"Shared by Test and Live"` informational badge. The environment toggle filters only environment-scoped views (`/dashboard/api-keys` and runtime user lists).

---

## 3. Data Tables, Drawers & Relationship Grids

1. **Browse in Paginated Tables:**
   * Built with accessible headless primitives (`@radix-ui` and `@tanstack/react-table`).
   * Explicit prerequisite: Install `@tanstack/react-table@^8.11.0` in Slice 1.
   * Supports server-side pagination, debounced search, column sorting, loading skeletons, and empty states.
2. **Edit in Side Drawers (`Sheet`):**
   * Creating or editing roles, permissions, webhooks, and provider credentials occurs in slide-over side drawers (`Sheet`), preserving background table context.
   * Drawer open state is synchronized with URL search params (`?drawer=edit-role&id=<id>`), ensuring browser Back button closes the drawer rather than navigating away, and supporting direct deep-linking.
3. **Roles-by-Permissions Matrix:**
   * Visual grid mapping project roles against permissions.
   * **Collapsible Namespace Accordions:** Permissions grouped by prefix (e.g. `users.*`, `auth.*`, `billing.*`) collapse into single summary rows (`users (4 of 6 granted)`) to prevent 2D grid overflow.
   * **Sticky Crosshairs:** Role column headers remain sticky on vertical scroll; permission name column remains sticky on horizontal scroll.
   * **Dual-View Toggle:** Accessible toggle between `[ Matrix View | List View ]`.
4. **Split-View Policy:**
   * Two-column split view is reserved strictly for short lists (<15 items). High-volume views always use full data tables.

---

## 4. Anti-AI Slop Heuristics & Contrast Compliance (WCAG 2.2 AA)

1. **Eliminate Eyebrows:** Ban uppercase tracking labels (`text-xs uppercase tracking-[0.18em]`). Replace with semantic sentence-case labels (`text-sm font-medium text-zinc-300`).
2. **Eliminate Pulsing Dots:** Ban `animate-ping` and oscillating rings. Use solid, high-contrast badges (`Active`, `Revoked`, `Expired`).
3. **Eliminate Sparkle Hype Icons:** Ban `Sparkles` and magic wands across setup prompts and keys. Use precise technical icons (`Terminal`, `KeyRound`, `ShieldCheck`).
4. **Color Tokens & Contrast Ratio:**
   * Canvas background: `#0A0A0F`
   * Panels / Drawers / Card surfaces: `#12111A`
   * Subtle borders: `#1E1535` / `#27272A`
   * Primary accent: `#7C3AED` (Interactive focus & buttons), text accent `#C4B5FD`
   * Muted body text: Upgrade from low-contrast `#71717A` (3.2:1) to `#A1A1AA` (4.6:1), meeting WCAG 2.2 AA.

---

## 5. Backend API Verification & Identified Gaps

| Endpoint | Backend View | Pagination Supported? | Search & Ordering? | Filter Fields | Notes / Gaps |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **API Keys** | `APIKeyListCreateView` | Yes (`PageNumberPagination`) | Yes (`name`, `prefix`) | `environment`, `is_active`, `project` | Fully supports server-side control plane. |
| **Project Roles** | `ProjectRoleListCreateView` | Yes (`PageNumberPagination`) | Yes (`slug`, `name`, `desc`) | None | Fully supports search and sorting. |
| **Project Permissions** | `ProjectPermissionListCreateView` | Yes (`PageNumberPagination`) | Yes (`slug`, `name`, `desc`) | None | Fully supports search and sorting. |
| **Users** | `UserListView` | Yes (`PageNumberPagination`) | Yes (`email`, names) | `role`, `is_active`, `is_test` | **Gap Identified:** Endpoint lacks `project` filter for JWT dashboard callers. Mitigation: Unified users table with Project column badge + separate backend PR task `TASK-BK-042`. |
| **Webhooks** | `WebhookListCreateView` | Yes (`PageNumberPagination`) | Yes | None | Fully supported. |
| **Audit Logs** | `AuditLogListView` | Yes (`PageNumberPagination`) | Yes | `event_type`, `user` | Fully supported. |

---

## 6. Forward-Compatible Roadmap Slots

The shell and routing structure natively provide slots for incoming backend capabilities:
* **Step 7 (Session Revocation & Device Management):** Account session cards + `/dashboard/users/:id` active session inspector with remote revoke triggers.
* **Step 8 (Workspaces / B2B Multi-Tenancy):** Header tenant switcher accommodating `Org` -> `Project` -> `Workspace`.
* **Step 9 (Enterprise SAML/SCIM & Agent Tokens):** Enterprise SSO configuration forms, SCIM sync logs, and delegated Agent Token management.

---

## 7. Execution Roadmap: 5 Vertical Slices

Each slice is delivered as an isolated, reviewable Pull Request with automated screenshots, leaving existing pages operational during migration:

* **Slice 1: App Shell, API Keys & Onboarding**
  * Prerequisites: `npm install @tanstack/react-table@^8.11.0`.
  * Layout shell: Header (breadcrumbs, project switcher with copyable Project ID, accessible Test/Live toggle) and left sidebar with `ProjectContext`.
  * Dual-plane API Keys page: Segmented tabs `[ Runtime Client Keys | Management Keys ]` with high-visibility security notice, scope bundling, show-once secret display, revoke dialog.
  * Onboarding Quickstart: 24-hour setup prompt key copy, CLI connection instructions pre-filled with the integration triad (`HVT_BASE_URL`, `HVT_PROJECT_ID`, `HVT_API_KEY`).
* **Slice 2: Roles & Permissions**
  * Roles-by-permissions matrix grid with collapsible namespace accordions and sticky crosshairs.
  * Paginated permissions table with debounced search and `[ Matrix View | List View ]` toggle.
  * URL-backed side drawer for role creation, permission assignment, and editing.
* **Slice 3: Users & Audit Logs**
  * Server-paginated Platform Users table and Runtime Users table (filtered by `is_test`).
  * User detail view with assigned roles, direct deletion, and future session revocation slot.
  * Audit logs table with event filtering, actor lookup, and expandable detail drawer.
* **Slice 4: Auth Methods, Providers, Email & Webhooks**
  * Decoupled Auth Methods settings: Passkeys, TOTP, Magic Links, Passwords.
  * Social Providers configuration cards with callback URL copy.
  * Bring-Your-Own Email Provider UI (SMTP, SES, Resend, Postmark) with interactive test dispatch.
  * Webhook management and delivery log table with payload inspector.
* **Slice 5: "Try It" Runtime Console & Polish**
  * Interactive authentication playground for developers to test login, passkeys, and token exchange.
  * Final accessibility audit (WCAG 2.2 AA), phone-width validation, and performance benchmarks.
