import {
  EncryptedVaultItemPayload,
  VaultItemDraft,
  VaultItemRecord,
  VaultSecret
} from "@lockmate/sdk";

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const IV_LENGTH = 12;

function getCrypto(): Crypto {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error("WebCrypto API is not available in this environment");
}

function base64ToBytes(value: string): Uint8Array {
  if (typeof atob !== "function") {
    throw new Error("Base64 decoding is not supported in this environment");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa !== "function") {
    throw new Error("Base64 encoding is not supported in this environment");
  }
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  const view =
    bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
      ? bytes
      : bytes.slice();
  return view.buffer as ArrayBuffer;
}

async function computeChecksum(payload: Uint8Array): Promise<string> {
  const crypto = getCrypto();
  const hashBuffer = await crypto.subtle.digest("SHA-256", toBufferSource(payload));
  const hashBytes = new Uint8Array(hashBuffer);
  return `sha256:${bytesToBase64(hashBytes)}`;
}

export async function deriveMasterKeyFromPassword(
  password: string,
  saltBase64: string
): Promise<CryptoKey> {
  const crypto = getCrypto();
  const saltBytes = base64ToBytes(saltBase64);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toBufferSource(saltBytes),
      iterations: 310_000,
      hash: "SHA-256"
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptVaultItemDraft(
  draft: VaultItemDraft,
  key: CryptoKey
): Promise<EncryptedVaultItemPayload> {
  const crypto = getCrypto();
  const plaintext = TEXT_ENCODER.encode(JSON.stringify(draft.secret ?? {}));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );
  const ciphertextBytes = new Uint8Array(ciphertextBuffer);
  const payload = new Uint8Array(iv.length + ciphertextBytes.length);
  payload.set(iv, 0);
  payload.set(ciphertextBytes, iv.length);

  const checksum = await computeChecksum(plaintext);

  return {
    label: draft.label,
    tags: draft.tags,
    checksum,
    ciphertext: bytesToBase64(payload)
  };
}

export async function decryptVaultItemRecord(
  record: VaultItemRecord,
  key: CryptoKey
): Promise<VaultSecret> {
  const crypto = getCrypto();
  const payload = base64ToBytes(record.ciphertext);
  if (payload.length <= IV_LENGTH) {
    throw new Error("Ciphertext is too short");
  }
  const iv = payload.slice(0, IV_LENGTH);
  const ciphertext = payload.slice(IV_LENGTH);
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  const plaintext = TEXT_DECODER.decode(plaintextBuffer);
  return JSON.parse(plaintext) as VaultSecret;
}
