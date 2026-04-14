# SDK Repository Split

The TypeScript SDK has been moved out of the backend repository so SDK contributors can work without cloning the Django codebase.

## Current State

- standalone SDK repository: [markodera/hvt-sdk](https://github.com/markodera/hvt-sdk)
- package name: `@hvt/sdk`
- backend repository keeps only a pointer in [`sdk/README.md`](../sdk/README.md)

## Why This Changed

- SDK contributors no longer need the backend repository
- SDK releases and issue tracking can happen independently
- backend and SDK versioning can evolve with clearer ownership

## Direct API Usage

Not every integration needs an SDK. Non-SDK languages can call the HTTP API directly:

- Main app: [hvts.app](https://hvts.app)
- API base URL: [api.hvts.app](https://api.hvts.app)
- Docs: [docs.hvts.app](https://docs.hvts.app)

## Backend Repository Follow-up

This backend repository should not carry SDK source anymore. It should:

1. link contributors to `markodera/hvt-sdk`
2. document `api.hvts.app` for direct integrations
3. keep platform and API docs focused on the backend service
