/**
 * Secure OTP Generation & Verification Service
 * Guarantees plain-text OTPs are NEVER stored. Only cryptographic hashes are retained.
 */

import { db } from '../config/db.ts';
import {
  generateSecureNumericOTP,
  hashOTP,
  verifyOTPHash
} from '../utils/encryption.ts';
import { sendEmailOTP } from './emailService.ts';
import { logger } from '../utils/logger.ts';
import { OTPRecord } from '../../types.ts';

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const OTP_RESEND_COOLDOWN_MS = 45 * 1000; // 45 seconds cooldown
const MAX_ATTEMPTS = 3;

/**
 * Generate and send a new OTP.
 */
export async function requestAndSendOTP(
  identifier: string,
  purpose: OTPRecord['purpose'],
  recipientName: string = 'Citizen'
): Promise<{
  success: boolean;
  message: string;
  cooldownRemaining?: number;
}> {
  const normalizedId = identifier.trim().toLowerCase();

  // Check existing OTP for resend cooldown
  const existing = await db.otps.findLatest(normalizedId, purpose);

  if (existing) {
    const elapsed = Date.now() - existing.createdAt;

    if (elapsed < OTP_RESEND_COOLDOWN_MS) {
      const remainingSeconds = Math.ceil(
        (OTP_RESEND_COOLDOWN_MS - elapsed) / 1000
      );

      return {
        success: false,
        message: `Please wait ${remainingSeconds} seconds before requesting a new OTP.`,
        cooldownRemaining: remainingSeconds
      };
    }
  }

  // Generate secure 6-digit OTP
  const rawOTP = generateSecureNumericOTP(6);

  // Hash OTP before storing it
  const otpHash = hashOTP(rawOTP, normalizedId);

  // Send email
  const emailResult = await sendEmailOTP({
    toEmail: normalizedId,
    recipientName,
    otpCode: rawOTP,
    purposeText:
      purpose === 'registration'
        ? 'Citizen Registration'
        : 'Account Authentication'
  });

  // Do not activate OTP if email delivery failed
  if (!emailResult.success) {
    logger.error(
      `OTP email delivery failed for ${normalizedId}. OTP was not activated.`
    );

    return {
      success: false,
      message:
        emailResult.message ||
        'Unable to send verification code. Please try again.'
    };
  }

  // Store only the OTP hash
  await db.otps.create({
    identifier: normalizedId,
    otpHash,
    purpose,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    verified: false,
    attempts: 0,
    maxAttempts: MAX_ATTEMPTS
  });

  logger.audit('OTP_GENERATED_AND_DISPATCHED', normalizedId, { purpose });

  return {
    success: true,
    message: `A 6-digit verification code has been sent to ${normalizedId}. It expires in 5 minutes.`
  };
}

/**
 * Verify an OTP submitted by the user.
 */
export async function verifySubmittedOTP(
  identifier: string,
  submittedOTP: string,
  purpose: OTPRecord['purpose']
): Promise<{ success: boolean; message: string }> {
  const normalizedId = identifier.trim().toLowerCase();

  // Find the latest OTP
  const record = await db.otps.findLatest(normalizedId, purpose);

  if (!record) {
    return {
      success: false,
      message: 'No verification code found. Please request a new OTP.'
    };
  }

  // Check expiry
  if (Date.now() > record.expiresAt) {
    await db.otps.delete(normalizedId, purpose);

    return {
      success: false,
      message: 'OTP has expired. Please request a new verification code.'
    };
  }

  // Check whether already verified
  if (record.verified) {
    return {
      success: false,
      message: 'This OTP has already been used. Please request a new code.'
    };
  }

  // Check maximum attempts
  if (record.attempts >= record.maxAttempts) {
    await db.otps.delete(normalizedId, purpose);

    return {
      success: false,
      message: 'Maximum verification attempts exceeded. Please request a new OTP.'
    };
  }

  // Verify submitted OTP against stored hash
  const isValid = verifyOTPHash(
    submittedOTP.trim(),
    normalizedId,
    record.otpHash
  );

  if (!isValid) {
    const attemptsMade = await db.otps.incrementAttempts(
      normalizedId,
      purpose
    );

    const attemptsLeft = Math.max(
      0,
      record.maxAttempts - attemptsMade
    );

    logger.audit('OTP_VERIFICATION_FAILED', normalizedId, {
      attemptsMade,
      attemptsLeft
    });

    return {
      success: false,
      message:
        attemptsLeft > 0
          ? `Invalid verification code. ${attemptsLeft} attempt(s) remaining.`
          : 'Invalid verification code. Please request a new OTP.'
    };
  }

  // Mark OTP as verified
  await db.otps.markVerified(normalizedId, purpose);

  logger.audit('OTP_VERIFIED_SUCCESSFULLY', normalizedId, { purpose });

  return {
    success: true,
    message: 'Email verification completed successfully.'
  };
}
