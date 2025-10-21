# Lockmate TypeScript SDK

This package provides a lightweight TypeScript wrapper for the Lockmate Password Manager REST API. It is intentionally minimal and focuses on request wiring, token lifecycle helpers, and hooks for pluggable client-side encryption.

## Installation

```bash
npm install @lockmate/sdk
```

## Usage

```ts
import { LockmateClient } from "@lockmate/sdk";

const client = new LockmateClient({
  baseUrl: "https://api.lockmate.io/api/v1",
  encryption: {
    async encryptItem(draft) {
      // Replace with project-specific encryption.
      return {
        label: draft.label,
        tags: draft.tags,
        checksum: draft.checksum,
        ciphertext: await encryptWithTeamKey(draft.secret)
      };
    },
    async decryptItem(record) {
      return {
        ...record,
        secret: await decryptWithTeamKey(record.ciphertext)
      };
    }
  }
});

const { token } = await client.login({ username: "jane", password: "P@ssw0rd!" });
client.setToken(token);

const vaults = await client.listVaultItems();
```

## Development

- `npm install`
- `npm run build`

By default, the SDK serializes vault item secrets to base64-encoded JSON when no encryption hooks are provided. Applications should override this behavior with project-specific cryptography before storing sensitive data.
