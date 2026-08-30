/**
 * Secure Private Document Storage Service
 *
 * Uses Supabase Storage for private document files.
 * Document metadata remains in the existing database.
 */

import crypto from "crypto";
import { db, activeDownloadTokens } from "../config/db.ts";
import { supabase } from "../config/supabase.ts";
import { DocumentItem } from "../../types.ts";

import {
  isAllowedMimeType,
  detectBufferMimeType,
  VALID_DOCUMENT_TYPES,
  MAX_DOCUMENT_FILE_SIZE
} from "../utils/validators.ts";

import { generateRandomToken } from "../utils/encryption.ts";
import { logger } from "../utils/logger.ts";

const STORAGE_BUCKET = "documents";

export async function uploadPrivateDocument(
  userId: string,
  documentType: DocumentItem["documentType"],
  title: string,
  originalFileName: string,
  mimeType: string,
  fileBuffer: Buffer
): Promise<{
  success: boolean;
  message: string;
  document?: DocumentItem;
}> {

  // -------------------------------------------------------------
  // 1. Validate document type
  // -------------------------------------------------------------

  if (!VALID_DOCUMENT_TYPES.includes(documentType)) {
    return {
      success: false,
      message: `Invalid document type. Allowed types: ${VALID_DOCUMENT_TYPES.join(", ")}`
    };
  }

  // -------------------------------------------------------------
  // 2. Validate MIME type
  // -------------------------------------------------------------

  if (!isAllowedMimeType(mimeType)) {
    return {
      success: false,
      message:
        `Unsupported file type (${mimeType}). ` +
        `Only PDF, JPEG, PNG, and WEBP documents are allowed.`
    };
  }

  // -------------------------------------------------------------
  // 3. Validate file
  // -------------------------------------------------------------

  if (!fileBuffer || fileBuffer.length === 0) {
    return {
      success: false,
      message: "Uploaded file is empty."
    };
  }

  if (fileBuffer.length > MAX_DOCUMENT_FILE_SIZE) {
    return {
      success: false,
      message:
        `File size exceeds the 10MB maximum limit. ` +
        `(File size: ${(fileBuffer.length / (1024 * 1024)).toFixed(2)} MB)`
    };
  }

  // -------------------------------------------------------------
  // 4. Verify file magic bytes
  // -------------------------------------------------------------

  const detectedType = detectBufferMimeType(fileBuffer);

  if (!detectedType) {
    logger.warn(
      `File upload rejected: magic-byte mismatch for file ${originalFileName}`
    );

    return {
      success: false,
      message:
        "File content signature could not be verified. " +
        "Allowed formats are valid PDF, JPEG, PNG, or WEBP files."
    };
  }

  // -------------------------------------------------------------
  // 5. Sanitize filename
  // -------------------------------------------------------------

  const sanitizedFileName = originalFileName.replace(
    /[^a-zA-Z0-9._-]/g,
    "_"
  );

  if (
    sanitizedFileName.includes("..") ||
    sanitizedFileName.includes("/") ||
    sanitizedFileName.includes("\\")
  ) {
    return {
      success: false,
      message: "Invalid or insecure file name format."
    };
  }

  // -------------------------------------------------------------
  // 6. Generate SHA-256 checksum
  // -------------------------------------------------------------

  const sha256Checksum = crypto
    .createHash("sha256")
    .update(fileBuffer)
    .digest("hex");

  // -------------------------------------------------------------
  // 7. Generate private Supabase storage path
  // -------------------------------------------------------------

  const storageKey =
    `vault/${userId}/` +
    `${Date.now()}_${generateRandomToken(8)}_${sanitizedFileName}`;

  // -------------------------------------------------------------
  // 8. Upload file to Supabase Storage
  // -------------------------------------------------------------

  const { error: uploadError } = await supabase.storage
    .from(STORAGE_BUCKET)
    .upload(storageKey, fileBuffer, {
      contentType: detectedType,
      cacheControl: "3600",
      upsert: false
    });

  if (uploadError) {
    logger.error(
      `Supabase document upload failed: ${uploadError.message}`
    );

    return {
      success: false,
      message: "Failed to upload document to secure storage."
    };
  }

  // -------------------------------------------------------------
  // 9. Store metadata in existing database
  // -------------------------------------------------------------

  try {
    const document = await db.documents.create({
      userId,
      documentType,
      title: title || sanitizedFileName,
      originalFileName: sanitizedFileName,
      mimeType: detectedType,
      fileSize: fileBuffer.length,
      storageKey,
      sha256Checksum,
      verificationStatus: "pending",
      verifiedVia: "manual"
    });

    logger.audit("DOCUMENT_UPLOADED_SECURELY", userId, {
      docId: document.id,
      type: documentType,
      fileSize: fileBuffer.length,
      checksum: sha256Checksum.slice(0, 12) + "...",
      storage: "supabase"
    });

    return {
      success: true,
      message: "Document securely uploaded to your private vault.",
      document
    };

  } catch (error: any) {

    // If database insertion fails, remove the uploaded file
    // so we don't leave an orphaned file in Supabase.

    await supabase.storage
      .from(STORAGE_BUCKET)
      .remove([storageKey]);

    logger.error(
      `Database document creation failed after Supabase upload: ${error?.message}`
    );

    return {
      success: false,
      message: "Document upload failed while saving document information."
    };
  }
}

/**
 * Creates a short-lived application-level download token.
 */
export async function createSignedDownloadUrl(
  documentId: string,
  userId: string
): Promise<{
  success: boolean;
  downloadUrl?: string;
  message?: string;
}> {

  const doc = await db.documents.findById(documentId);

  if (!doc) {
    return {
      success: false,
      message: "Document not found."
    };
  }

  // Strict ownership check
  if (doc.userId !== userId) {
    logger.warn(
      `Unauthorized document access attempt. User: ${userId} tried to access Doc: ${documentId}`
    );

    return {
      success: false,
      message:
        "Unauthorized access. You can only view your own documents."
    };
  }

  // Generate 15-minute application token
  const token = generateRandomToken(24);

  const expiresAt = Date.now() + 15 * 60 * 1000;

  activeDownloadTokens.set(token, {
    documentId,
    userId,
    expiresAt
  });

  const downloadUrl =
    `/api/documents/${documentId}/download?token=${token}`;

  return {
    success: true,
    downloadUrl
  };
}

/**
 * Downloads the document from private Supabase Storage.
 */
export async function getDocumentStream(
  documentId: string,
  token: string,
  requestingUserId?: string
): Promise<{
  success: boolean;
  buffer?: Buffer;
  mimeType?: string;
  fileName?: string;
  error?: string;
}> {

  // -------------------------------------------------------------
  // 1. Validate application token
  // -------------------------------------------------------------

  const tokenRecord = activeDownloadTokens.get(token);

  if (!tokenRecord) {
    return {
      success: false,
      error: "Invalid or expired download token."
    };
  }

  if (Date.now() > tokenRecord.expiresAt) {
    activeDownloadTokens.delete(token);

    return {
      success: false,
      error: "Download token has expired."
    };
  }

  if (tokenRecord.documentId !== documentId) {
    return {
      success: false,
      error: "Token does not match requested document."
    };
  }

  if (
    requestingUserId &&
    tokenRecord.userId !== requestingUserId
  ) {
    return {
      success: false,
      error: "User ownership verification failed."
    };
  }

  // -------------------------------------------------------------
  // 2. Get document metadata
  // -------------------------------------------------------------

  const doc = await db.documents.findById(documentId);

  if (!doc) {
    return {
      success: false,
      error: "Document record not found in database."
    };
  }

  // Additional ownership check
  if (doc.userId !== tokenRecord.userId) {
    return {
      success: false,
      error: "Document ownership verification failed."
    };
  }

  // -------------------------------------------------------------
  // 3. Download from Supabase Storage
  // -------------------------------------------------------------

  const { data, error } = await supabase.storage
    .from(STORAGE_BUCKET)
    .download(doc.storageKey);

  if (error || !data) {

    logger.error(
      `Supabase document download failed: ${error?.message}`
    );

    return {
      success: false,
      error: "Document file could not be retrieved from secure storage."
    };
  }

  // -------------------------------------------------------------
  // 4. Convert Blob to Buffer
  // -------------------------------------------------------------

  const arrayBuffer = await data.arrayBuffer();

  const buffer = Buffer.from(arrayBuffer);

  return {
    success: true,
    buffer,
    mimeType: doc.mimeType || "application/octet-stream",
    fileName: doc.originalFileName
  };
}
