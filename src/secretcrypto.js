const crypto = require('crypto');

// Separate key used ONLY to encrypt/decrypt the AGENT_SHARED_SECRET at rest
// in Supabase. Must be different from AGENT_SHARED_SECRET itself -- encrypting
// a secret with itself provides no real protection.
// Generate with: openssl rand -hex 32
const RAW_KEY = process.env.SECRET_ENCRYPTION_KEY;

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // recommended IV length for GCM

function getKeyBuffer() {
  if (!RAW_KEY) {
    throw new Error('SECRET_ENCRYPTION_KEY is not set. Cannot encrypt/decrypt secrets.');
  }
  const keyBuffer = Buffer.from(RAW_KEY, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error('SECRET_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).');
  }
  return keyBuffer;
}

/**
 * Encrypts a plaintext string. Returns a single string safe to store in a
 * TEXT column: "<iv_hex>:<authtag_hex>:<ciphertext_hex>"
 */
function encryptSecret(plaintext) {
  const key = getKeyBuffer();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return [iv.toString('hex'), authTag.toString('hex'), ciphertext.toString('hex')].join(':');
}

/**
 * Decrypts a string produced by encryptSecret(). Throws if the data has been
 * tampered with (GCM auth tag mismatch) or the key is wrong.
 */
function decryptSecret(stored) {
  const key = getKeyBuffer();
  const parts = stored.split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted secret format.');
  }
  const [ivHex, authTagHex, ciphertextHex] = parts;

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString('utf8');
}

module.exports = { encryptSecret, decryptSecret };