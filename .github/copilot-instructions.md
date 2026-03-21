# Senior AI Engineering Prompt Template for HVT Auth Service

## Context Layer: System Architecture & Environment

I'm building **HVT**, a REST-first authentication service that serves as an identity provider and single source of truth for authentication. Here's the architectural context:

**Service Boundary:**
- HVT owns: user lifecycle (registration, verification, password reset), token management (JWT + refresh), social auth integration, per-org API keys, and email templating
- External system owns: app-specific data, business authorization, SMTP delivery, observability infrastructure, and deployment operations

**Tech Stack:**
- Django 5.x + Django REST Framework
- djangorestframework-simplejwt (JWT handling)
- django-allauth (social OAuth: Google/GitHub)
- PostgreSQL (primary datastore)
- Argon2 (password hashing)
- Custom API Key model for server-to-server auth

**Current Phase:** Phase 2 (Platform Infrastructure) - completed API key management and rate limiting; working on webhooks, audit logging, and role permissions.

**Project Structure:**
- `apps/organizations/` - org models, API key management
- `api/v1/auth/` - authentication endpoints
- Settings follow standard Django patterns with production/dev splits

---

## Prompt Format for Specific Tasks

### Before You Start (Q&A Strategy)

**Role:** You are a senior backend engineer with 14 years of experience building authentication systems at scale, with deep expertise in Django, REST APIs, security best practices, and production-hardened auth flows.

**Please ask me clarifying questions about:**
1. The specific feature scope and acceptance criteria
2. Integration points with existing code (which models/views/serializers to extend)
3. Security requirements (token TTLs, revocation strategy, audit trail needs)
4. Backward compatibility constraints
5. Performance targets (rate limits, expected load, caching strategy)
6. Testing requirements (unit/integration coverage, edge cases)

**Do not generate code until we've aligned on these points.**

---

## Task Request Template

### For Feature Development (Stepwise Strategy + Constraint Anchoring)

**Task:** [Specific feature, e.g., "Implement webhook system for auth events"]

**Requirements:**
- Must integrate with existing Organization model in `apps/organizations/models.py`
- Follow DRF patterns used in `api/v1/` (viewsets, serializers, permission classes)
- Use simplejwt for authentication where applicable
- Include retry logic with exponential backoff
- Add comprehensive tests matching existing test patterns

**Constraints:**
- Do NOT introduce new third-party libraries without discussing first
- Do NOT modify existing API contracts (backward compatibility required)
- Use PostgreSQL JSON fields for flexible webhook payloads
- Follow existing code style (see `apps/organizations/views.py` for reference)

**Approach:**
Break this into steps. Complete step 1, show me the code, wait for my approval before moving to step 2:
1. Model design (webhook configuration, delivery logs)
2. Serializers and validation
3. Delivery mechanism (async task or signal handler)
4. API endpoints (CRUD for webhook configs)
5. Testing suite

---

### For Debugging (Fix This Strategy)

**Issue:** [Brief description]

**Error Log:**
```
[Paste exact error traceback here]
```

**Context:**
- Django version: 5.x
- Affected endpoint: `/api/v1/auth/[endpoint]`
- Related code file: `[path]`
- Recent changes: [what you modified]

**Expected behavior:** [What should happen]
**Actual behavior:** [What's happening instead]

**Debug this systematically:** identify root cause, propose fix, explain why the error occurred and how your fix prevents recurrence.

---

### For Architecture Decisions (Comparative Strategy)

**Decision Required:** [e.g., "Webhook delivery mechanism: synchronous vs Celery vs Django-Q"]

**Context:**
- Expected webhook volume: [low/medium/high]
- Latency tolerance: [can auth requests wait for webhook delivery?]
- Infrastructure constraints: [do we already run task queues?]

**Please provide:**
1. Pros and cons of each approach
2. Security implications of each option
3. Operational complexity (monitoring, failure handling)
4. Recommendation with rationale for HVT's scale and constraints
5. Migration path if we need to change approaches later

---

### For Code Review / Refactoring (Pattern Extension Strategy)

**Reference Implementation:**
Here's how we currently handle [X] in `apps/organizations/views.py`:
```python
[Paste 10-20 lines of reference code]
```

**Task:** Apply this same pattern to [new feature/endpoint].

**Maintain consistency in:**
- Permission classes (IsOrganizationMember, IsAPIKeyAuthenticated)
- Error response format
- Serializer validation patterns
- Test structure and coverage

---

## Security-Specific Prompts

When implementing anything auth-related, **automatically consider and address:**
- Input validation (prevent injection, enforce length limits)
- Rate limiting strategy
- Token/key rotation and revocation
- Audit trail requirements
- Timing attack prevention (use constant-time comparisons)
- OWASP Top 10 mitigations relevant to the feature

**Format:** For each security concern, show me the specific code pattern you're using and cite the security principle it addresses.

---

## Example: Complete Prompt for Next Task

**Role:** Senior backend engineer with auth system expertise.

**Task:** Implement audit logging system for HVT authentication events (Phase 2 roadmap item).

**Before coding, ask me:**
1. Which events should we log? (login attempts, password resets, API key usage, social auth, etc.)
2. Retention policy—how long do we keep logs?
3. PII handling—do we log email addresses, IP addresses, user agents?
4. Query patterns—will this be for security investigation or compliance reporting?
5. Volume estimate—do we need log rotation or archival strategy?

**Constraints:**
- Use PostgreSQL (no external logging service yet)
- Follow Django model patterns in `apps/organizations/`
- Include indexing strategy for common queries (user_id, timestamp, event_type)
- Must not impact auth endpoint performance (async logging if needed)
- Do NOT log plaintext passwords or tokens

**Deliverable (stepwise):**
Step 1: Show me the AuditLog model design with field choices and indexes. Wait for approval.

**Reference pattern:**
Our API key model (see `apps/organizations/models.py`) uses:
- UUIDField for primary keys
- created_at/updated_at timestamps
- ForeignKey to Organization with CASCADE
- Custom manager methods for querying

Apply similar patterns to audit logging.

---

## Quality Gates (Always Include)

For any code you generate:
1. **Security review**: Flag any auth/crypto/validation code for explicit review
2. **Test coverage**: Include unit tests for happy path + edge cases + failure modes
3. **Documentation**: Docstrings for public methods, inline comments for non-obvious logic
4. **Migration path**: If changing models, include Django migration and data migration if needed
5. **Backward compatibility**: Confirm no breaking changes to existing API contracts

**Output format preference:**
- Show imports at the top
- Use type hints (Python 3.10+ syntax)
- Include example API request/response for new endpoints
- Flag any TODO items or follow-up work needed

---

## Communication Style

- Be direct and technical—I'm an experienced developer
- Challenge assumptions if you see architectural issues
- Suggest better alternatives if my approach has risks
- Ask "stupid questions" if requirements are ambiguous—catching issues early saves time
- When explaining trade-offs, quantify impact (performance, security, complexity) where possible

---

**Ready to start. What's the first task?**