# Lockmate Password Manager API

Lockmate is an Axum-based API for managing password vault users. It includes
basic user management operations, SurrealDB persistence, and now JWT-backed
session handling for protected routes.

## Getting started

1. Install Rust (latest stable toolchain).
2. Run `cargo run` from the project root. The server listens on
   `http://127.0.0.1:10002` by default.
3. A SurrealDB instance must be available at `localhost:10001` (see
   `docker-compose.yml` for a local development setup).

## Environment variables

| Name | Required | Default | Description |
| ---- | -------- | ------- | ----------- |
| `JWT_SECRET` | ✅ | _none_ | Secret key for signing session tokens. Use a strong random value. |
| `JWT_EXPIRATION_MINUTES` | ❌ | `60` | Token lifetime in minutes. Reduce this for stricter session durations. |

All variables can be placed inside a `.env` file in the project root. They are
loaded automatically at startup via [`dotenvy`](https://crates.io/crates/dotenvy).

## Authentication workflow

* `POST /api/users/login/`
  * Accepts a JSON body containing `username` and `password`.
  * Returns the authenticated user (without the password hash) and a `token`
    field containing a signed JWT. Store this token client-side.
* `POST /api/users/logout/`
  * Requires an `Authorization: Bearer <token>` header.
  * Revokes the presented token so it can no longer be used.
* `GET /api/users/`
  * Requires an `Authorization: Bearer <token>` header.
  * Returns the list of users, with password hashes stripped.

When calling protected routes, always include the bearer token returned by the
login endpoint:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

If a token is missing, expired, revoked, or invalid, the API responds with a
`401 Unauthorized` status and a JSON body describing the failure.

## API contract

The full REST contract for version 1 of the service is documented in
[`docs/api/v1.md`](docs/api/v1.md). It covers authentication, vault management,
item operations, and sharing workflows.

## TypeScript SDK

A companion SDK is available under [`sdk/`](sdk/). It exposes a lightweight
client for the documented REST API along with hooks for custom encryption. See
[`sdk/README.md`](sdk/README.md) for usage instructions.

## Development scripts

* `cargo fmt` — format the codebase.
* `cargo test` — run the test suite, including password hashing and JWT service
  coverage.
