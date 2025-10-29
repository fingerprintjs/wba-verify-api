/**
 * Test suite for validly signed requests
 * Tests cryptographic signature verification using RFC 9421 test keys
 * 
 * IMPORTANT: Requires the test server to serve the public key directory
 * at /.well-known/http-message-signatures-directory
 * 
 * Run with: npm run test:signed
 */

import axios from 'axios';
import { signatureHeaders } from 'web-bot-auth';
import { Ed25519Signer } from 'web-bot-auth/crypto';

// RFC 9421 Ed25519 Test Key (Full key with private component for signing)
// Source: https://datatracker.ietf.org/doc/html/rfc9421#appendix-B.1.4
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

async function testSignedRequest(baseUrl: string) {
  console.log('\nTesting Signed Request');
  console.log('='.repeat(80));
  console.log(`Endpoint: ${baseUrl}/api/verify`);

  try {
    // Parse URL to get components
    const url = new URL(`${baseUrl}/api/verify`);
    
    // Create request object for signing
    const requestToSign = {
      method: 'GET',
      url: url.toString(),
      headers: {
        'host': url.host,
        'content-type': 'application/json',
      },
    };

    console.log('\nStep 1: Creating signature...');
    
    // Import the private key as a CryptoKey
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      RFC_9421_ED25519_TEST_KEY,
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      } as any,
      false,
      ['sign']
    );
    
    // Create signer with the correct keyid
    const signer = new Ed25519Signer(RFC_9421_ED25519_TEST_KEY.kid, privateKey);
    
    // Generate signature headers
    const now = new Date();
    const headers = await signatureHeaders(
      requestToSign,
      signer,
      {
        created: now,
        expires: new Date(now.getTime() + 300_000), // now + 5 min
      }
    );

    console.log('  Signature created');
    console.log(`  Signature: ${headers['Signature']?.substring(0, 50)}...`);
    console.log(`  Signature-Input: ${headers['Signature-Input']?.substring(0, 80)}...`);

    console.log('\nStep 2: Sending signed request...');

    // Make the request with signature headers
    const response = await axios.get(`${baseUrl}/api/verify`, {
      headers: {
        'Signature': headers['Signature'],
        'Signature-Input': headers['Signature-Input'],
        'Signature-Agent': baseUrl,
        'Host': url.host,
        'Content-Type': 'application/json',
      },
      validateStatus: () => true,
    });

    console.log(`\nStep 3: Response received`);
    console.log(`  HTTP Status: ${response.status}`);
    console.log(`\nResponse Body:`);
    console.log(JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.status === 'success') {
      console.log('\n✓ SUCCESS: Signature was verified!\n');
      return true;
    } else {
      console.log('\n✗ FAILED: Signature verification failed');
      console.log('  This might be due to URL/host mismatch or other signature issues.\n');
      return false;
    }

  } catch (error: any) {
    console.log(`\n✗ ERROR: ${error.message}\n`);
    
    if (error.response) {
      console.log(`  Response Status: ${error.response.status}`);
      console.log(`  Response Data:`);
      console.log(JSON.stringify(error.response.data, null, 2));
    }
    
    return false;
  }
}

async function main() {
  const baseUrl = process.argv[2] || 'http://localhost:3000';

  console.log('\nWBA Signed Request Test Suite');
  console.log('='.repeat(80));
  console.log(`Base URL: ${baseUrl}`);

  const result = await testSignedRequest(baseUrl);

  console.log('='.repeat(80));
  console.log(`\nTest Result: ${result ? 'PASSED' : 'FAILED'}\n`);

  process.exit(result ? 0 : 1);
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
