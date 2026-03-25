/**
 * Test suite for invalid request handling
 * Tests error cases: missing headers, malformed signatures, etc.
 * 
 * Run with: npm run test:invalid
 */

import { webBotAuthSignatureInput } from './signature-input-fixtures';

interface TestCase {
  name: string;
  headers: Record<string, string>;
  expectedStatus: number;
  expectedErrorCode: string;
}

const testCases: TestCase[] = [
  {
    name: 'Missing all signature headers',
    headers: {
      'Content-Type': 'application/json',
    },
    expectedStatus: 400,
    expectedErrorCode: 'MISSING_SIGNATURE_HEADERS',
  },
  {
    name: 'Missing Signature header',
    headers: {
      'Signature-Input': webBotAuthSignatureInput({
        createdSec: 1234567890,
        expiresSec: 1234568190,
        keyid: 'test-key-ed25519',
      }),
    },
    expectedStatus: 400,
    expectedErrorCode: 'MISSING_SIGNATURE_HEADERS',
  },
  {
    name: 'Missing Signature-Input header',
    headers: {
      'Signature': 'sig1=:invalid:',
    },
    expectedStatus: 400,
    expectedErrorCode: 'MISSING_SIGNATURE_HEADERS',
  },
  {
    name: 'Missing Signature-Agent header',
    headers: {
      'Signature': 'sig1=:invalidsignature:',
      'Signature-Input': webBotAuthSignatureInput({
        createdSec: Math.floor(Date.now() / 1000),
        expiresSec: Math.floor(Date.now() / 1000) + 300,
        keyid: 'test-key-ed25519',
      }),
    },
    expectedStatus: 400,
    expectedErrorCode: 'MISSING_SIGNATURE_AGENT',
  },
  {
    name: 'Key directory fetch fails (example.com Signature-Agent)',
    headers: {
      'Signature': 'sig1=:invalidsignature:',
      'Signature-Input': webBotAuthSignatureInput({
        createdSec: Math.floor(Date.now() / 1000),
        expiresSec: Math.floor(Date.now() / 1000) + 300,
        keyid: 'test-key-ed25519',
      }),
      'Signature-Agent': 'https://example.com',
    },
    expectedStatus: 400,
    expectedErrorCode: 'KEY_DIRECTORY_FETCH_FAILED',
  },
  {
    name: 'Signature-Input: empty covered components',
    headers: {
      'Signature': 'sig1=:dummysignature:',
      'Signature-Input': `sig1=();created=${Math.floor(Date.now() / 1000)};expires=${Math.floor(Date.now() / 1000) + 300};keyid="kid";alg="ed25519";nonce="n";tag="web-bot-auth"`,
      'Signature-Agent': 'http://localhost:3000',
    },
    expectedStatus: 400,
    expectedErrorCode: 'INVALID_SIGNATURE_INPUT',
  },
  {
    name: 'Signature-Input: tag is not web-bot-auth',
    headers: {
      'Signature': 'sig1=:dummysignature:',
      'Signature-Input': webBotAuthSignatureInput({
        createdSec: Math.floor(Date.now() / 1000),
        expiresSec: Math.floor(Date.now() / 1000) + 300,
        keyid: 'test-key-ed25519',
        tag: 'wrong-tag',
      }),
      'Signature-Agent': 'http://localhost:3000',
    },
    expectedStatus: 400,
    expectedErrorCode: 'INVALID_SIGNATURE_INPUT',
  },
  {
    name: 'Signature-Input: unquoted covered component',
    headers: {
      'Signature': 'sig1=:dummysignature:',
      'Signature-Input': `sig1=(@authority "signature-agent");created=${Math.floor(Date.now() / 1000)};expires=${Math.floor(Date.now() / 1000) + 300};keyid="kid";alg="ed25519";nonce="Mj311bOYjyItNPeGy0GYLA==";tag="web-bot-auth"`,
      'Signature-Agent': 'http://localhost:3000',
    },
    expectedStatus: 400,
    expectedErrorCode: 'INVALID_SIGNATURE_INPUT',
  },
];

async function runTests(baseUrl: string = 'http://localhost:3000') {
  console.log('Testing Invalid Request Handling\n');
  console.log(`Base URL: ${baseUrl}\n`);
  console.log('='.repeat(80));

  let passed = 0;
  let failed = 0;

  for (const testCase of testCases) {
    console.log(`\nTest: ${testCase.name}`);

    try {
      const response = await fetch(`${baseUrl}/api/verify`, {
        method: 'GET',
        headers: testCase.headers,
      });

      const result: any = await response.json();
      
      // Check status code
      const statusMatches = response.status === testCase.expectedStatus;
      
      // Check error code
      const hasExpectedError = result.errors?.some(
        (err: any) => err.code === testCase.expectedErrorCode
      );

      if (statusMatches && hasExpectedError) {
        console.log(`  ✓ PASSED`);
        console.log(`    Status: ${response.status}`);
        console.log(`    Error: ${result.errors[0].code} - ${result.errors[0].message}`);
        passed++;
      } else {
        console.log(`  ✗ FAILED`);
        console.log(`    Expected status: ${testCase.expectedStatus}, got: ${response.status}`);
        console.log(`    Expected error: ${testCase.expectedErrorCode}`);
        console.log(`    Response: ${JSON.stringify(result, null, 2)}`);
        failed++;
      }
    } catch (error: any) {
      console.log(`  ✗ FAILED - Exception: ${error.message}`);
      failed++;
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(`\nResults: ${passed} passed, ${failed} failed (${testCases.length} total)`);
  
  if (failed === 0) {
    console.log('All tests passed!\n');
  } else {
    console.log('Some tests failed.\n');
  }

  return { passed, failed, total: testCases.length };
}

if (require.main === module) {
  const baseUrl = process.argv[2] || 'http://localhost:3000';

  runTests(baseUrl)
    .then(results => {
      process.exit(results.failed === 0 ? 0 : 1);
    })
    .catch(error => {
      console.error('Fatal error:', error);
      process.exit(1);
    });
}

export { runTests, testCases };

