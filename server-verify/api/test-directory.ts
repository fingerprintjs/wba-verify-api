/**
 * Mock directory endpoint for testing
 * Serves the RFC 9421 test key for local testing purposes
 */

import type { VercelRequest, VercelResponse } from '@vercel/node';

// RFC 9421 Ed25519 Test Key (public key only)
const TEST_RFC_9421_PUBLIC_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

/**
 * Test directory endpoint that serves RFC 9421 test keys
 * Available at: /.well-known/http-message-signatures-directory
 * 
 * This is a mock endpoint for testing purposes only.
 */
export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Set CORS headers for testing
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader(
    'Content-Type',
    'application/http-message-signatures-directory+json; charset=utf-8'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Return the test directory with the RFC 9421 test key
  const directory = {
    keys: [TEST_RFC_9421_PUBLIC_KEY],
    purpose: "test"
  };

  res.status(200).json(directory);
}

