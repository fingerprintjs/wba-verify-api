/**
 * Signature validation module for HTTP Message Signatures
 * Implements Step 2 of the validation flow: validate the signature based on trust-on-first-use
 * Uses the web-bot-auth library for signature verification
 */

import type { VercelRequest, VercelResponse } from '@vercel/node';
import { verify } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";
import { fetchSignaturesDirectory, findKeyById, validateSignatureAgent } from "./directory";
import type { ValidationResult, ValidationConfig, SignaturesDirectory, SignatureComponents, JWK } from "./types";

/**
 * Main validation function that implements the complete two-step flow:
 * 1. Fetch the directory with signature-agent
 * 2. Validate the signature based on trust-on-first-use
 *
 * @param request - The incoming HTTP request to validate
 * @param config - Validation configuration
 * @returns Promise<ValidationResult> - The validation result
 */
export async function validateWebBotAuth(request: Request, config: ValidationConfig): Promise<ValidationResult> {
  const details = {
    signatureFound: false,
    directoryFetched: false,
    keyMatched: false,
    signatureValid: false,
  };

  try {
    // Step 1: Check if signature headers are present
    const signatureComponents = extractSignatureComponents(request);
    if (!signatureComponents) {
      return {
        isValid: false,
        error: "No HTTP Message Signature headers found",
        details,
      };
    }
    details.signatureFound = true;

    // Step 1.5: Validate signature timestamps (RFC 9421 Section 3.3)
    const timestampValidation = validateSignatureTimestamps(signatureComponents);
    if (!timestampValidation.isValid) {
      return {
        isValid: false,
        error: timestampValidation.error || "Signature timestamp validation failed",
        details,
      };
    }

    // Step 2: Fetch the signatures directory
    const directoryResult = await fetchSignaturesDirectory(config.directoryUrl, config.cacheTimeout);
    if (!directoryResult.success || !directoryResult.directory) {
      return {
        isValid: false,
        error: `Failed to fetch signatures directory: ${directoryResult.error}`,
        details,
      };
    }
    details.directoryFetched = true;

    // Step 3: Find the matching key
    const key = findKeyById(directoryResult.directory, signatureComponents.keyId || "");
    if (!key) {
      return {
        isValid: false,
        error: `No matching key found for kid: ${signatureComponents.keyId}`,
        details,
      };
    }
    details.keyMatched = true;

    // Step 4: Validate the signature using web-bot-auth
    const signatureValid = await verifySignatureWithWebBotAuth(request, key, directoryResult.directory);
    if (!signatureValid) {
      return {
        isValid: false,
        error: "Signature verification failed",
        details: { ...details, signatureValid: false },
      };
    }
    details.signatureValid = true;

    // Step 5: Validate purpose if specified
    if (config.purpose && directoryResult.directory.purpose !== config.purpose) {
      return {
        isValid: false,
        error: `Purpose mismatch: expected "${config.purpose}", got "${directoryResult.directory.purpose}"`,
        details: { ...details, signatureValid: true },
      };
    }

    return {
      isValid: true,
      details,
      metadata: {
        kid: signatureComponents.keyId,
        purpose: directoryResult.directory.purpose,
        timestamp: new Date().toISOString(),
      },
    };
  } catch (error) {
    return {
      isValid: false,
      error: `Validation error: ${error instanceof Error ? error.message : String(error)}`,
      details,
    };
  }
}

/**
 * Validates signature timestamps according to RFC 9421 Section 3.3
 * - expires: Must be in the future
 * - created: Must not be too far in the past or future
 *
 * @param components - Extracted signature components
 * @returns Validation result with error message if invalid
 */
function validateSignatureTimestamps(components: SignatureComponents): { isValid: boolean; error?: string } {
  const now = Math.floor(Date.now() / 1000); // Current time in Unix seconds

  // RFC 9421 Section 3.3: Validate expires parameter
  if (components.expires) {
    const expiresTime = parseInt(components.expires, 10);
    if (isNaN(expiresTime)) {
      return { isValid: false, error: "Invalid expires timestamp format" };
    }
    
    if (expiresTime <= now) {
      const expiredDate = new Date(expiresTime * 1000).toISOString();
      return { 
        isValid: false, 
        error: `Signature has expired (expired at ${expiredDate}, current time is ${new Date(now * 1000).toISOString()})` 
      };
    }
  }

  // RFC 9421 Section 3.3: Validate created parameter
  if (components.created) {
    const createdTime = parseInt(components.created, 10);
    if (isNaN(createdTime)) {
      return { isValid: false, error: "Invalid created timestamp format" };
    }

    // Reject if created time is more than 5 minutes in the future
    const maxFutureSkew = 300; // 5 minutes
    if (createdTime > now + maxFutureSkew) {
      return { 
        isValid: false, 
        error: `Signature created timestamp is too far in the future (created: ${new Date(createdTime * 1000).toISOString()}, current: ${new Date(now * 1000).toISOString()})` 
      };
    }

    // Reject if created time is more than 1 hour in the past
    const maxAgeSeconds = 3600; // 1 hour
    if (createdTime < now - maxAgeSeconds) {
      return { 
        isValid: false, 
        error: `Signature created timestamp is too old (created: ${new Date(createdTime * 1000).toISOString()}, max age: 1 hour)` 
      };
    }
  }

  return { isValid: true };
}

/**
 * Extracts signature components from the HTTP request headers
 *
 * @param request - The HTTP request
 * @returns SignatureComponents or null if not found
 */
function extractSignatureComponents(request: Request): SignatureComponents | null {
  const signature = request.headers.get("signature");
  const signatureInput = request.headers.get("signature-input");

  if (!signature || !signatureInput) {
    return null;
  }

  // Parse signature-input to extract key information
  const keyIdMatch = signatureInput.match(/keyid="([^"]+)"/);
  const algorithmMatch = signatureInput.match(/alg="([^"]+)"/);
  const createdMatch = signatureInput.match(/created=(\d+)/);
  const expiresMatch = signatureInput.match(/expires=(\d+)/);
  const nonceMatch = signatureInput.match(/nonce="([^"]+)"/);
  const tagMatch = signatureInput.match(/tag="([^"]+)"/);

  return {
    signature,
    signatureInput,
    keyId: keyIdMatch ? keyIdMatch[1] : undefined,
    algorithm: algorithmMatch ? algorithmMatch[1] : undefined,
    created: createdMatch ? createdMatch[1] : undefined,
    expires: expiresMatch ? expiresMatch[1] : undefined,
    nonce: nonceMatch ? nonceMatch[1] : undefined,
    tag: tagMatch ? tagMatch[1] : undefined,
  };
}

/**
 * Verifies the signature using the web-bot-auth library
 * This implements trust-on-first-use validation
 *
 * @param request - The HTTP request to verify
 * @param key - The JWK to use for verification
 * @param directory - The signatures directory
 * @returns Promise<boolean> - True if signature is valid
 */
async function verifySignatureWithWebBotAuth(request: Request, key: JWK, directory: SignaturesDirectory): Promise<boolean> {
  try {
    // Create a verifier from the JWK
    const verifier = await verifierFromJWK(key);

    // Use web-bot-auth's verify function
    // This implements the trust-on-first-use approach
    await verify(request, verifier);

    return true;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

// ============================================================================
// Vercel Serverless Function Handler
// ============================================================================

interface ErrorDetail {
  code: string;
  message: string;
}

interface VerificationResponse {
  status: 'success' | 'error';
  errors?: ErrorDetail[];
  details?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    timestamp: string;
    keyId?: string;
    keySource?: string;
  };
}

/**
 * Helper function to safely extract header value from VercelRequest
 * Handles the case where headers might be string | string[] | undefined
 * Preserves exact byte-level representation for cryptographic verification
 * 
 * @param value - Header value from VercelRequest
 * @returns string or undefined
 */
function getHeaderValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

/**
 * Converts VercelRequest to Web Request object
 * CRITICAL: Preserves exact header values for cryptographic signature verification
 * 
 * @param req - Vercel request object
 * @returns Request object with exact header byte representation
 */
function createRequestForVerification(req: VercelRequest): Request {
  // Extract headers with exact byte-level preservation
  const signature = getHeaderValue(req.headers['signature']);
  const signatureInput = getHeaderValue(req.headers['signature-input']);
  const signatureAgent = getHeaderValue(req.headers['signature-agent']);
  
  // Create Headers object with exact values (no normalization)
  const headers = new Headers();
  if (signature) headers.set('Signature', signature);
  if (signatureInput) headers.set('Signature-Input', signatureInput);
  if (signatureAgent) headers.set('Signature-Agent', signatureAgent);
  
  // Construct a proper absolute URL for the Request constructor
  // In Vercel, req.url might be just a path, so we need to build a full URL
  const host = getHeaderValue(req.headers['host']) || 'localhost';
  const protocol = host.includes('localhost') ? 'http' : 'https';
  const path = req.url || '/';
  const fullUrl = path.startsWith('http') ? path : `${protocol}://${host}${path}`;
  const method = req.method || 'GET';
  
  return new Request(fullUrl, {
    method,
    headers,
  });
}

/**
 * Vercel serverless function handler for Web Bot Auth verification
 * 
 * This endpoint validates HTTP Message Signatures using the trust-on-first-use approach.
 * It fetches the public key from the signature-agent's well-known directory and verifies
 * the cryptographic signature on the request headers.
 * 
 * Expected headers:
 * - signature: The HTTP Message Signature
 * - signature-input: Signature metadata and parameters
 * - signature-agent: The domain to fetch the public key from
 */
export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // ---------------------------------------------------------------------------
  // CORS headers (must be first, before any returns)
  // ---------------------------------------------------------------------------
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Signature, Signature-Input, Signature-Agent'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  // ---------------------------------------------------------------------------
  const errors: ErrorDetail[] = [];

  try {
    // Step 1: Validate required headers are present
    const signatureHeader = req.headers['signature'];
    const signatureInputHeader = req.headers['signature-input'];
    const signatureAgentHeader = req.headers['signature-agent'];

    if (!signatureHeader || !signatureInputHeader || !signatureAgentHeader) {
      errors.push({
        code: 'MISSING_SIGNATURE_HEADERS',
        message: 'Required headers `Signature`, `Signature-Input`, and `Signature-Agent` are missing'
      });
      res.status(400).json({
        status: 'error',
        errors
      } as VerificationResponse);
      return;
    }

    // Step 2: Extract signature-agent domain (handle array case)
    const signatureAgent = getHeaderValue(signatureAgentHeader);
    if (!signatureAgent) {
      errors.push({
        code: 'INVALID_SIGNATURE_AGENT',
        message: 'signature-agent header is empty'
      });
      res.status(400).json({
        status: 'error',
        errors
      } as VerificationResponse);
      return;
    }

    // Step 3: Validate signature-agent format
    // Must be a root domain with https protocol
    const domain = signatureAgent.replace(/"/g, '').trim();
    
    // Validate domain format
    const agentValidation = validateSignatureAgent(domain);
    if (!agentValidation.isValid) {
      errors.push({
        code: 'INVALID_SIGNATURE_AGENT',
        message: agentValidation.error || 'Invalid signature-agent format'
      });
      res.status(400).json({
        status: 'error',
        errors
      } as VerificationResponse);
      return;
    }

    // Step 4: Construct directory URL from signature-agent
    const directoryUrl = `${domain}/.well-known/http-message-signatures-directory`;

    // Step 5: Create Request object with exact header preservation for cryptographic verification
    const requestForVerification = createRequestForVerification(req);

    // Step 6: Validate using the core validation logic
    const config: ValidationConfig = {
      directoryUrl,
      cacheTimeout: 60 * 60 * 1000, // 1 hour cache
    };

    const validationResult = await validateWebBotAuth(requestForVerification, config);

    // Step 7: Map ValidationResult to VerificationResponse format
    if (validationResult.isValid) {
      // Success response
      res.status(200).json({
        status: 'success',
        details: {
          method: req.method || 'GET',
          url: req.url || '/',
          headers: {
            'signature': typeof signatureHeader === 'string' 
              ? signatureHeader.substring(0, 50) + '...' 
              : (Array.isArray(signatureHeader) ? signatureHeader[0].substring(0, 50) + '...' : ''),
            'signature-input': typeof signatureInputHeader === 'string'
              ? signatureInputHeader.substring(0, 100) + '...'
              : (Array.isArray(signatureInputHeader) ? signatureInputHeader[0].substring(0, 100) + '...' : ''),
          },
          timestamp: new Date().toISOString(),
          keyId: validationResult.metadata?.kid,
          keySource: `directory: ${directoryUrl}`
        }
      } as VerificationResponse);
      return;
    } else {
      // Validation failed - determine specific error code
      let errorCode = 'VALIDATION_FAILED';
      
      if (!validationResult.details?.signatureFound) {
        errorCode = 'MISSING_SIGNATURE_HEADERS';
      } else if (validationResult.error?.includes('expired')) {
        errorCode = 'SIGNATURE_EXPIRED';
      } else if (validationResult.error?.includes('too old')) {
        errorCode = 'SIGNATURE_TOO_OLD';
      } else if (validationResult.error?.includes('too far in the future')) {
        errorCode = 'SIGNATURE_TIMESTAMP_FUTURE';
      } else if (!validationResult.details?.directoryFetched) {
        errorCode = 'KEY_DIRECTORY_FETCH_FAILED';
      } else if (validationResult.error?.includes('Key has expired')) {
        errorCode = 'KEY_EXPIRED';
      } else if (validationResult.error?.includes('Key is not yet valid')) {
        errorCode = 'KEY_NOT_YET_VALID';
      } else if (!validationResult.details?.keyMatched) {
        errorCode = 'KEY_NOT_FOUND';
      } else if (!validationResult.details?.signatureValid) {
        errorCode = 'VERIFICATION_FAILED';
      }

      errors.push({
        code: errorCode,
        message: validationResult.error || 'Validation failed'
      });

      res.status(400).json({
        status: 'error',
        errors
      } as VerificationResponse);
      return;
    }

  } catch (error: any) {
    errors.push({
      code: 'INTERNAL_ERROR',
      message: `Internal server error: ${error.message || 'Unknown error occurred'}`
    });

    res.status(500).json({
      status: 'error',
      errors
    } as VerificationResponse);
    return;
  }
}