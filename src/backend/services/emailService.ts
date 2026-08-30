import nodemailer from 'nodemailer';
import { logger } from '../utils/logger.ts';

interface SendOtpOptions {
  toEmail: string;
  recipientName: string;
  otpCode: string;
  purposeText?: string;
}

export const lastDevEmailDeliveries: Array<{
  email: string;
  timestamp: string;
  purpose: string;
  otpForTestingOnly: string;
}> = [];

export async function sendEmailOTP({
  toEmail,
  recipientName,
  otpCode,
  purposeText = 'Account Registration & Verification'
}: SendOtpOptions): Promise<{ success: boolean; message: string }> {
  const host = process.env.EMAIL_HOST;
  const port = Number(process.env.EMAIL_PORT || 587);
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASSWORD;
  const from = process.env.EMAIL_FROM || user;

  // Safe configuration check — does not print passwords or secrets
  console.log('Email configuration check:', {
    host: host || 'MISSING',
    port,
    userConfigured: Boolean(user),
    passwordConfigured: Boolean(pass),
    from: from || 'MISSING'
  });

  try {
    if (!host || !user || !pass || !from) {
      logger.error('Email configuration is incomplete.');

      return {
        success: false,
        message:
          'Unable to send verification email. Email configuration is incomplete.'
      };
    }

    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: {
        user,
        pass
      }
    });

    // Verify the SMTP connection before attempting to send the OTP
    await transporter.verify();

    await transporter.sendMail({
      from: `"YojanaSetu AI" <${from}>`,
      to: toEmail,
      subject: `${otpCode} - Your YojanaSetu Verification Code`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Email Verification</h2>
          <p>Hello ${recipientName},</p>
          <p>Your verification code for <strong>${purposeText}</strong> is:</p>
          <h1 style="letter-spacing: 5px;">${otpCode}</h1>
          <p>This code expires in 5 minutes.</p>
          <p>If you did not request this code, please ignore this email.</p>
        </div>
      `
    });

    logger.info(`OTP email sent successfully to ${toEmail}`);

    return {
      success: true,
      message: `Verification code sent successfully to ${toEmail}`
    };
  } catch (err: any) {
    // Log the real error only on the backend terminal
    console.error('Gmail SMTP error:', err?.message || err);
    logger.error(`SMTP email dispatch failed: ${err?.message || err}`);

    return {
      success: false,
      message:
        'Unable to send verification email. Please check the server email configuration and Gmail authentication.'
    };
  }
}
