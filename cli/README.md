# @hvt/cli

> Official CLI for HVT — AI-native declarative schema provisioning, plan previews, and auth synchronization.  
> **SPDX-License-Identifier: Apache-2.0**

---

## Installation

Run directly with `npx` (no global installation required):

```bash
npx @hvt/cli --help
```

Or install globally:

```bash
npm install -g @hvt/cli
```

---

## Quickstart

### 1. Initialize Schema
In your project repository, run:

```bash
npx @hvt/cli init
```

This generates a starter `hvt.schema.json` declaring your roles, permissions, auth methods, and social providers.

### 2. Configure Credentials
Add your Project ID and Management Key to your `.env` or `.env.local` file:

```bash
HVT_PROJECT_ID="your-project-uuid"
HVT_MANAGEMENT_KEY="hvt_mgmt_test_..."
```

### 3. Preview Changes (Dry-Run)
Inspect what will be created, adopted, reconciled, or pruned without making any changes:

```bash
npx @hvt/cli schema plan
```

### 4. Synchronize Schema Live
Apply your authorization schema to HVT:

```bash
npx @hvt/cli schema sync
```

On first sync, the CLI automatically retrieves your runtime client key and writes it to `.env.local` as `NEXT_PUBLIC_HVT_CLIENT_KEY`.

---

## Commands

| Command | Description |
| :--- | :--- |
| `hvt init` | Generates a starter `hvt.schema.json` manifest. |
| `hvt schema plan` | Previews proposed schema changes (dry-run). |
| `hvt schema sync` | Reconciles local schema with HVT Cloud. |
| `hvt whoami` | Verifies credentials and connectivity to HVT. |

---

## Flags & Options

* `--prune`: Deletes manifest-owned objects that are omitted from your schema file.
* `-y, --yes`: Confirms pruning automatically (required in non-interactive CI/CD runs).
* `--issue-client-key`: Mints an additional runtime client key even if one is active.
* `--api-url <url>`: Override API base URL (defaults to `https://api.hvts.app`).
* `--key <key>`: Supply management key via CLI flag instead of environment variable.
* `--project <id>`: Supply project ID via CLI flag instead of environment variable.
* `--schema <path>`: Explicit path to `hvt.schema.json` or `hvt.schema.yaml`.
* `--json`: Outputs structured JSON for CI scripts and AI agents.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
