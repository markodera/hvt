# HVT Performance & Platform Evolution (Brainstorm Intake)

* **Author:** Engineering Team / Agent Benchmark Review
* **Date:** 2026-11-07
* **Status:** Initial Brainstorm Intake (Step 1)

## Overview

A stress-test report from an integration agent benchmarked HVT at 50 concurrent workers against local endpoints. While the capability rejection path performed efficiently (650 req/s), session resolution capped at ~510 req/s due to synchronous round-trips to the runtime plane.

The report identifies three primary engineering opportunities:
1. **Offline Cryptographic Token Verification (JWKS / Asymmetric RS256/EdDSA JWTs):** Eliminating network hops for downstream token validation.
2. **Sandbox / Test Environment Auto-Confirm:** Bypassing email delivery checks when operating under `environment: test` to ensure frictionless local/CI testing.
3. **Official Framework Middleware Adapters:** Providing `@hvt/next` and `@hvt/express` packages to remove manual token extraction boilerplate.

## Analysis

### 1. Token Verification Bottleneck
- Currently, token validation downstream requires either sharing the symmetric `SECRET_KEY` (an architectural anti-pattern in distributed architectures) or calling `/api/v1/auth/runtime/me/` on every request.
- Moving to RS256 or Ed25519 with a standard `/.well-known/jwks.json` endpoint allows microservices and edge gateways to verify signatures locally using cached public keys.

### 2. Test-Mode Email Gating
- Currently, test projects still trigger email verification workflows. If Resend or SMTP credentials are omitted during development or CI pipelines, registration fails.
- Auto-confirming users or providing a deterministic mock mailbox in test projects removes a common point of developer friction.

### 3. Client Adapter Surface
- While `@hvt/sdk` is zero-dependency, developers building modern Next.js 14+ (App Router) or Express services must manually implement cookie extraction, header parsing, and redirect guards.

## Goals vs. Non-Goals

* **In-Scope Goals (To Be Scoped During Brainstorming):**
  - Define architectural priority among the three opportunities.
  - Establish security, key rotation, and performance requirements for asymmetric JWT / JWKS issuance.
  - Define test-mode verification bypass boundaries.
* **Out-of-Scope Non-Goals:**
  - Rewriting existing database schemas.
  - Replacing the core `@hvt/sdk` protocol.

## Open Questions for Clarification
1. Should this brainstorm prioritize the high-throughput performance bottleneck (JWKS / Asymmetric JWTs) first, or developer onboarding friction (Test-mode auto-confirm & SDK framework adapters)?
2. What are the key rotation and revocation invariants needed if asymmetric tokens are verified offline?
3. How should test-mode auto-confirm ensure zero accidental bypass in production live mode?
