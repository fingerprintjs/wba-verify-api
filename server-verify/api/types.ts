/**
 * Type definitions for Web Bot Auth validation flow
 * Based on RFC 9421 and web-bot-auth library specifications
 */

/**
 * JSON Web Key (JWK) structure as defined in RFC 7517
 */
export interface JWK {
    kty: string; // Key Type
    kid?: string; // Key ID
    use?: string; // Public Key Use
    key_ops?: string[]; // Key Operations
    alg?: string; // Algorithm
    x5u?: string; // X.509 URL
    x5c?: string[]; // X.509 Certificate Chain
    x5t?: string; // X.509 Certificate SHA-1 Thumbprint
    "x5t#S256"?: string; // X.509 Certificate SHA-256 Thumbprint
    crv?: string; // Curve (for OKP keys)
    x?: string; // X coordinate (for OKP keys)
    y?: string; // Y coordinate (for EC keys)
    n?: string; // Modulus (for RSA keys)
    e?: string; // Exponent (for RSA keys)
    nbf?: number; // Not Before (Unix timestamp in milliseconds)
    exp?: number; // Expiration (Unix timestamp in milliseconds)
  }
  
  /**
   * HTTP Message Signatures Directory structure
   * Based on the research website specification
   */
  export interface SignaturesDirectory {
    keys: JWK[];
    purpose?: string; // Purpose of the signatures (e.g., "rag")
  }
  
  /**
   * Configuration options for validation
   */
  export interface ValidationConfig {
    directoryUrl: string; // URL to fetch the signatures directory
    purpose?: string; // Expected purpose for validation
    cacheTimeout?: number; // Cache timeout in milliseconds (default: 1 hour)
  }
  
  /**
   * Error codes returned by validateWebBotAuth (HTTP handler maps these to API responses)
   */
  export type ValidationErrorCode =
    | 'MISSING_SIGNATURE_HEADERS'
    | 'INVALID_SIGNATURE_INPUT'
    | 'SIGNATURE_EXPIRED'
    | 'SIGNATURE_TOO_OLD'
    | 'SIGNATURE_TIMESTAMP_FUTURE'
    | 'VALIDATION_FAILED'
    | 'KEY_DIRECTORY_FETCH_FAILED'
    | 'INVALID_DIRECTORY_CONTENT_TYPE'
    | 'KEY_EXPIRED'
    | 'KEY_NOT_YET_VALID'
    | 'KEY_NOT_FOUND'
    | 'VERIFICATION_FAILED';

  /**
   * Validation result structure
   */
  export interface ValidationResult {
    isValid: boolean;
    /** Set on every failed validation */
    errorCode?: ValidationErrorCode;
    error?: string;
    details?: {
      signatureFound: boolean;
      directoryFetched: boolean;
      keyMatched: boolean;
      signatureValid: boolean;
    };
    metadata?: {
      kid?: string;
      purpose?: string;
      timestamp?: string;
    };
  }
  
  /**
   * Directory fetching result
   */
  export interface DirectoryResult {
    success: boolean;
    directory?: SignaturesDirectory;
    error?: string;
    /** When success is false, optional machine-readable reason (e.g. wrong Content-Type) */
    errorCode?: ValidationErrorCode;
    url: string;
    timestamp: number;
  }
  
  /**
   * Signature validation context
   */
  export interface SignatureContext {
    request: Request;
    config: ValidationConfig;
    directory?: SignaturesDirectory;
  }
  
  /**
   * HTTP Message Signature header components
   */
  export interface SignatureComponents {
    signature: string;
    signatureInput: string;
    keyId?: string;
    algorithm?: string;
    created?: string;
    expires?: string;
    nonce?: string;
    tag?: string;
  }