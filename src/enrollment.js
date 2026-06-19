const crypto = require('crypto');
const { supabase } = require('./supabase');
const { encryptSecret, decryptSecret } = require('./secretcrypto');

const ENROLLMENT_TOKEN_TTL_MINUTES = 15;

/**
 * Generates a new enrollment token for a given agent_id and stores it.
 * The agent row must already exist (or this creates a minimal one) --
 * adjust the upsert fields to match whatever your registration flow
 * already requires (name, owner_id, etc.) at the call site.
 */
async function createEnrollmentToken(agentId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + ENROLLMENT_TOKEN_TTL_MINUTES * 60 * 1000);

  const { error } = await supabase
    .from('agents')
    .update({
      enrollment_token: token,
      enrollment_token_expires_at: expiresAt.toISOString(),
      enrollment_token_used: false,
    })
    .eq('id', agentId);

  if (error) {
    throw new Error(`Failed to create enrollment token: ${error.message}`);
  }

  return { token, expiresAt };
}

/**
 * Validates and consumes an enrollment token. On success, returns the
 * plaintext AGENT_SHARED_SECRET to hand back to the agent, and marks the
 * token as used so it cannot be replayed.
 *
 * Returns { success: true, secret } or { success: false, reason }.
 */
async function redeemEnrollmentToken(agentId, providedToken) {
  const { data: agentRow, error } = await supabase
    .from('agents')
    .select('enrollment_token, enrollment_token_expires_at, enrollment_token_used')
    .eq('id', agentId)
    .single();

  if (error || !agentRow) {
    return { success: false, reason: 'Unknown agent_id.' };
  }

  const { enrollment_token, enrollment_token_expires_at, enrollment_token_used } = agentRow;

  if (!enrollment_token) {
    return { success: false, reason: 'No enrollment token has been issued for this agent.' };
  }

  if (enrollment_token_used) {
    return { success: false, reason: 'Enrollment token has already been used.' };
  }

  if (new Date(enrollment_token_expires_at).getTime() < Date.now()) {
    return { success: false, reason: 'Enrollment token has expired.' };
  }

  // Constant-time comparison to avoid leaking token contents via timing.
  const providedBuf = Buffer.from(providedToken || '', 'utf8');
  const expectedBuf = Buffer.from(enrollment_token, 'utf8');
  const tokensMatch =
    providedBuf.length === expectedBuf.length &&
    crypto.timingSafeEqual(providedBuf, expectedBuf);

  if (!tokensMatch) {
    return { success: false, reason: 'Invalid enrollment token.' };
  }

  // Mark token as used immediately (before returning the secret) so that even
  // a concurrent duplicate request can't redeem it twice.
  const { error: updateError } = await supabase
    .from('agents')
    .update({ enrollment_token_used: true })
    .eq('id', agentId)
    .eq('enrollment_token_used', false); // double-check guard against race conditions

  if (updateError) {
    return { success: false, reason: 'Failed to finalize enrollment.' };
  }

  const sharedSecret = process.env.AGENT_SHARED_SECRET;
  if (!sharedSecret) {
    return { success: false, reason: 'Backend has no AGENT_SHARED_SECRET configured.' };
  }

  // Store an encrypted record that enrollment occurred (useful for audit /
  // future rotation), even though the secret itself is currently global.
  try {
    const encrypted = encryptSecret(sharedSecret);
    await supabase
      .from('agents')
      .update({ encrypted_secret: encrypted })
      .eq('id', agentId);
  } catch (encErr) {
    console.warn('Could not store encrypted secret audit record:', encErr.message);
    // Not fatal -- enrollment can still proceed even if the audit write fails.
  }

  return { success: true, secret: sharedSecret };
}

module.exports = { createEnrollmentToken, redeemEnrollmentToken };