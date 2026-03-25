/**
 * Directory fetching module for HTTP Message Signatures
 * Implements Step 1 of the validation flow: fetch the directory with signature-agent
 */

import type { SignaturesDirectory, DirectoryResult, JWK } from "./types";

/** Required Content-Type for HTTP Message Signatures directory JSON (see spec / interop). */
export const HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON =
  "application/http-message-signatures-directory+json";

// In-memory cache for directory results
const directoryCache = new Map<string, { data: SignaturesDirectory; timestamp: number }>();

/**
 * Validates the directory response Content-Type (media type only; parameters like charset allowed).
 */
export function validateDirectoryResponseContentType(
  contentTypeHeader: string | null
): { ok: true } | { ok: false; error: string } {
  if (contentTypeHeader == null || contentTypeHeader.trim() === "") {
    return {
      ok: false,
      error: `Missing Content-Type header (expected ${HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON})`,
    };
  }
  const mediaType = contentTypeHeader.split(";")[0].trim().toLowerCase();
  const expected = HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON.toLowerCase();
  if (mediaType !== expected) {
    return {
      ok: false,
      error: `Invalid Content-Type: expected ${HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON}, got ${contentTypeHeader.trim()}`,
    };
  }
  return { ok: true };
}

/**
 * Fetches the HTTP Message Signatures directory from the specified URL
 * This implements the first step of the validation flow
 *
 * @param url - The URL to fetch the directory from (e.g., https://example.com/.well-known/http-message-signatures-directory)
 * @param cacheTimeout - Cache timeout in milliseconds (default: 1 hour)
 * @returns Promise<DirectoryResult> - The directory fetching result
 */
export async function fetchSignaturesDirectory(
  url: string,
  cacheTimeout: number = 60 * 60 * 1000 // 1 hour default
): Promise<DirectoryResult> {
  const timestamp = Date.now();

  try {
    // Check cache first
    const cached = directoryCache.get(url);
    if (cached && timestamp - cached.timestamp < cacheTimeout) {
      return {
        success: true,
        directory: cached.data,
        url,
        timestamp: cached.timestamp,
      };
    }

    // Fetch the directory with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
    
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: `${HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON}, application/json;q=0.5`,
        "User-Agent": "fingerprint.com-wba-validator/1.0",
      },
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        success: false,
        error: `Failed to fetch directory: ${response.status} ${response.statusText}`,
        url,
        timestamp,
      };
    }

    const ctCheck = validateDirectoryResponseContentType(response.headers.get("content-type"));
    if (!ctCheck.ok) {
      return {
        success: false,
        error: ctCheck.error,
        errorCode: "INVALID_DIRECTORY_CONTENT_TYPE",
        url,
        timestamp,
      };
    }

    const data = await response.json();

    // Validate directory structure
    const validationResult = validateDirectoryStructure(data);
    if (!validationResult.isValid) {
      return {
        success: false,
        error: `Invalid directory structure: ${validationResult.error}`,
        url,
        timestamp,
      };
    }

    const directory = data as SignaturesDirectory;

    // Cache the result
    directoryCache.set(url, { data: directory, timestamp });

    return {
      success: true,
      directory,
      url,
      timestamp,
    };
  } catch (error) {
    return {
      success: false,
      error: `Error fetching directory: ${error instanceof Error ? error.message : String(error)}`,
      url,
      timestamp,
    };
  }
}

/**
 * Validates the structure of the signatures directory
 * Ensures it conforms to the expected format
 *
 * @param data - The parsed JSON data from the directory
 * @returns Object with validation result
 */
function validateDirectoryStructure(data: any): { isValid: boolean; error?: string } {
  if (!data || typeof data !== "object") {
    return { isValid: false, error: "Directory data is not an object" };
  }

  if (!Array.isArray(data.keys)) {
    return { isValid: false, error: 'Directory must contain a "keys" array' };
  }

  if (data.keys.length === 0) {
    return { isValid: false, error: "Directory keys array cannot be empty" };
  }

  // Validate each key in the array
  for (let i = 0; i < data.keys.length; i++) {
    const key = data.keys[i];
    const keyValidation = validateJWK(key);
    if (!keyValidation.isValid) {
      return {
        isValid: false,
        error: `Invalid key at index ${i}: ${keyValidation.error}`,
      };
    }
  }

  return { isValid: true };
}

/**
 * Validates a JSON Web Key (JWK) structure
 * Ensures it has the required fields for Ed25519 keys
 *
 * @param key - The JWK to validate
 * @returns Object with validation result
 */
function validateJWK(key: any): { isValid: boolean; error?: string } {
  if (!key || typeof key !== "object") {
    return { isValid: false, error: "Key is not an object" };
  }

  // Check required fields for Ed25519 keys
  if (key.kty !== "OKP") {
    return { isValid: false, error: 'Key type must be "OKP" for Ed25519' };
  }

  if (key.crv !== "Ed25519") {
    return { isValid: false, error: 'Curve must be "Ed25519"' };
  }

  if (!key.x || typeof key.x !== "string") {
    return { isValid: false, error: 'Missing or invalid "x" coordinate' };
  }

  if (!key.kid || typeof key.kid !== "string") {
    return { isValid: false, error: 'Missing or invalid "kid" (Key ID)' };
  }

  // Validate timestamp fields if present
  if (key.nbf !== undefined && typeof key.nbf !== "number") {
    return { isValid: false, error: 'Invalid "nbf" (Not Before) timestamp' };
  }

  if (key.exp !== undefined && typeof key.exp !== "number") {
    return { isValid: false, error: 'Invalid "exp" (Expiration) timestamp' };
  }

  // Enforce timestamp constraints (RFC 7517 + best practices)
  const now = Math.floor(Date.now() / 1000); // Current time in Unix seconds

  // Check if key is not yet valid (nbf - not before)
  if (key.nbf !== undefined && key.nbf > now) {
    const nbfDate = new Date(key.nbf * 1000).toISOString();
    return { 
      isValid: false, 
      error: `Key is not yet valid (not before: ${nbfDate}, current time: ${new Date(now * 1000).toISOString()})` 
    };
  }

  // Check if key has expired (exp - expiration)
  if (key.exp !== undefined && key.exp <= now) {
    const expDate = new Date(key.exp * 1000).toISOString();
    return { 
      isValid: false, 
      error: `Key has expired (expired at: ${expDate}, current time: ${new Date(now * 1000).toISOString()})` 
    };
  }

  return { isValid: true };
}

/**
 * Finds a key in the directory by its Key ID (kid)
 *
 * @param directory - The signatures directory
 * @param kid - The Key ID to search for
 * @returns The matching JWK or undefined if not found
 */
export function findKeyById(directory: SignaturesDirectory, kid: string): JWK | undefined {
  return directory.keys.find((key) => key.kid === kid);
}

/**
 * Clears the directory cache
 * Useful for testing or when cache needs to be refreshed
 */
export function clearDirectoryCache(): void {
  directoryCache.clear();
}

/**
 * Gets cache statistics
 * Useful for debugging and monitoring
 */
export function getCacheStats(): { size: number; entries: string[] } {
  return {
    size: directoryCache.size,
    entries: Array.from(directoryCache.keys()),
  };
}

/**
 * Validates the signature-agent header format
 * Ensures it's a properly formatted HTTPS root domain
 * 
 * @param agent - The signature-agent value to validate
 * @returns Validation result with error message if invalid
 */
export function validateSignatureAgent(agent: string): { isValid: boolean; error?: string } {
  // Check for empty or whitespace-only strings
  if (!agent || agent.trim().length === 0) {
    return { isValid: false, error: 'signature-agent cannot be empty' };
  }

  // Try to parse as URL
  let url: URL;
  try {
    url = new URL(agent);
  } catch (error) {
    return { isValid: false, error: 'signature-agent must be a valid URL (e.g., https://example.com)' };
  }

  // Must use HTTPS protocol (except localhost for testing)
  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !isLocalhost) {
    return { isValid: false, error: 'signature-agent must use HTTPS protocol' };
  }

  // Allow http for localhost testing
  if (isLocalhost && url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { isValid: false, error: 'signature-agent must use HTTP or HTTPS for localhost' };
  }

  // Must be a root domain (no path, query, or fragment)
  if (url.pathname !== '/' && url.pathname !== '') {
    return { isValid: false, error: 'signature-agent must be a root domain without path (e.g., https://example.com, not https://example.com/path)' };
  }

  if (url.search || url.hash) {
    return { isValid: false, error: 'signature-agent must not contain query parameters or fragments' };
  }

  // Validate hostname format (basic check)
  const hostname = url.hostname;
  if (!hostname || hostname.length === 0) {
    return { isValid: false, error: 'signature-agent must have a valid hostname' };
  }

  // Hostname should not contain invalid characters
  const validHostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!isLocalhost && !validHostnameRegex.test(hostname)) {
    return { isValid: false, error: 'signature-agent has invalid hostname format' };
  }

  // Must not have port specified (use default 443 for https)
  if (url.port && !isLocalhost) {
    return { isValid: false, error: 'signature-agent must not specify a port (use default HTTPS port 443)' };
  }

  return { isValid: true };
}