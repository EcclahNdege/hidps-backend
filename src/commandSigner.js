const crypto = require('crypto');

// Must match AGENT_SHARED_SECRET on the agent side exactly.
const AGENT_SHARED_SECRET = process.env.AGENT_SHARED_SECRET;

/**
 * Produces a canonical JSON string with sorted keys and no extra whitespace,
 * matching Python's json.dumps(payload, sort_keys=True, separators=(",", ":")).
 *
 * This has to recursively sort keys at every nesting level, not just the
 * top level, or signatures will silently mismatch for nested payloads.
 */
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJSON).join(',') + ']';
  }
  const sortedKeys = Object.keys(value).sort();
  const entries = sortedKeys.map(
    (key) => JSON.stringify(key) + ':' + canonicalJSON(value[key])
  );
  return '{' + entries.join(',') + '}';
}

/**
 * Signs a command the same way the agent's verify_command_signature expects:
 * HMAC-SHA256(secret, "{timestamp}:{command}:{canonical_payload}")
 *
 * Returns the full envelope ready to send: { command, payload, timestamp, id, signature }
 */
function signCommand(command, payload = {}) {
  if (!AGENT_SHARED_SECRET) {
    throw new Error('AGENT_SHARED_SECRET is not set. Refusing to send unsigned commands.');
  }

  const timestamp = Date.now() / 1000; // seconds, matching Python's time.time()
  const id = crypto.randomUUID();
  const canonicalPayload = canonicalJSON(payload);
  const message = `${timestamp}:${command}:${canonicalPayload}`;

  const signature = crypto
    .createHmac('sha256', AGENT_SHARED_SECRET)
    .update(message, 'utf8')
    .digest('hex');

  return { command, payload, timestamp, id, signature };
}

module.exports = { signCommand, canonicalJSON };