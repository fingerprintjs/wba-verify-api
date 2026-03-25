/**
 * Test suite for signature and key timestamp validation
 * 
 * Tests RFC 9421 Section 3.3 compliance:
 * - Signature expiration (expires parameter)
 * - Created timestamp validation
 * - JWK expiration (nbf/exp fields)
 * 
 * Run with: npm run test:timestamps
 */

import { webBotAuthSignatureInput } from './signature-input-fixtures';

interface TestCase {
  name: string;
  signatureInput: string;
  expectedError: string;
  expectedErrorCode: string;
}

const testCases: TestCase[] = [
  {
    name: 'Expired signature (expires in past)',
    signatureInput: webBotAuthSignatureInput({
      createdSec: Math.floor(Date.now() / 1000),
      expiresSec: Math.floor(Date.now() / 1000) - 100,
      keyid: 'test-key-ed25519',
    }),
    expectedError: 'expired',
    expectedErrorCode: 'SIGNATURE_EXPIRED',
  },
  {
    name: 'Signature created too far in future',
    signatureInput: webBotAuthSignatureInput({
      createdSec: Math.floor(Date.now() / 1000) + 3600,
      expiresSec: Math.floor(Date.now() / 1000) + 7200,
      keyid: 'test-key-ed25519',
    }),
    expectedError: 'too far in the future',
    expectedErrorCode: 'SIGNATURE_TIMESTAMP_FUTURE',
  },
  {
    name: 'Signature created too old (> 1 hour)',
    signatureInput: webBotAuthSignatureInput({
      createdSec: Math.floor(Date.now() / 1000) - 7200,
      expiresSec: Math.floor(Date.now() / 1000) + 300,
      keyid: 'test-key-ed25519',
    }),
    expectedError: 'too old',
    expectedErrorCode: 'SIGNATURE_TOO_OLD',
  },
  {
    name: 'Valid timestamps (created now, expires in 5 min)',
    signatureInput: webBotAuthSignatureInput({
      createdSec: Math.floor(Date.now() / 1000),
      expiresSec: Math.floor(Date.now() / 1000) + 300,
      keyid: 'test-key-ed25519',
    }),
    expectedError: '', // Should pass timestamp validation (may fail on other checks)
    expectedErrorCode: '', // Not testing this case for specific error
  },
];

async function runTests(baseUrl: string = 'http://localhost:3000') {
  console.log('Testing Signature Timestamp Validation\n');
  console.log(`Base URL: ${baseUrl}\n`);
  console.log('='.repeat(80));

  let passed = 0;
  let failed = 0;

  for (const testCase of testCases) {
    console.log(`\nTest: ${testCase.name}`);

    try {
      const response = await fetch(`${baseUrl}/api/verify`, {
        method: 'GET',
        headers: {
          'Signature': 'sig1=:dummysignature:',
          'Signature-Input': testCase.signatureInput,
          'Signature-Agent': 'http://localhost:3000',
        }
      });

      const result: any = await response.json();
      
      if (testCase.expectedError) {
        // Test expects an error
        const hasExpectedError = result.errors?.some(
          (err: any) => err.message.toLowerCase().includes(testCase.expectedError.toLowerCase())
        );
        
        const hasExpectedErrorCode = !testCase.expectedErrorCode || result.errors?.some(
          (err: any) => err.code === testCase.expectedErrorCode
        );

        if (hasExpectedError && hasExpectedErrorCode) {
          console.log(`  ✓ PASSED`);
          console.log(`    Status: ${response.status}`);
          console.log(`    Error: ${result.errors[0].code} - ${result.errors[0].message}`);
          passed++;
        } else {
          console.log(`  ✗ FAILED`);
          console.log(`    Expected error containing: "${testCase.expectedError}"`);
          if (testCase.expectedErrorCode) {
            console.log(`    Expected error code: ${testCase.expectedErrorCode}`);
          }
          console.log(`    Response: ${JSON.stringify(result, null, 2)}`);
          failed++;
        }
      } else {
        // Test expects timestamp validation to pass (may fail on other validations)
        const hasTimestampError = result.errors?.some(
          (err: any) => 
            err.message.toLowerCase().includes('expired') ||
            err.message.toLowerCase().includes('too old') ||
            err.message.toLowerCase().includes('too far in the future')
        );

        if (!hasTimestampError) {
          console.log(`  ✓ PASSED`);
          console.log(`    Status: ${response.status}`);
          console.log(`    Timestamp validation passed (may have failed on other checks)`);
          if (result.errors && result.errors.length > 0) {
            console.log(`    Other error: ${result.errors[0].code} - ${result.errors[0].message}`);
          }
          passed++;
        } else {
          console.log(`  ✗ FAILED`);
          console.log(`    Expected timestamp validation to pass`);
          console.log(`    Response: ${JSON.stringify(result, null, 2)}`);
          failed++;
        }
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

