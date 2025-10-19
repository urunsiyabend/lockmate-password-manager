# Lockmate Web Client

This package contains a Vite-powered React application that integrates with the Lockmate API
using the local `@lockmate/sdk`. The client performs login, vault browsing, and vault item
decryption directly in the browser with WebCrypto.

## Available scripts

```bash
npm install   # install dependencies
npm run dev   # start a local development server on http://localhost:5173
npm run build # type-check and create a production build in dist/
npm run preview # preview the production build locally
```

## Environment configuration

Set `VITE_API_BASE_URL` to point to the Lockmate backend (defaults to
`http://localhost:3000/api/v1`). The value can be stored in a `.env` file at the project root.

```bash
VITE_API_BASE_URL="http://localhost:3000/api/v1"
```

## Encryption

The client derives an AES-GCM key from the login password and the `key_salt` returned by the
backend. All vault item secrets are encrypted before upload and decrypted locally after download
using WebCrypto via helper utilities in `src/lib/encryption.ts`.
