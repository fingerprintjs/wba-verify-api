/**
 * Test suite for signature-agent header validation (14 tests)
 * 
 * Tests the signature-agent validation logic that ensures:
 * - HTTPS protocol is required (except localhost)
 * - Must be a root domain (no paths, query params, etc.)
 * - Proper URL format
 * 
 * Run with: npm run test:signature-agent
 */

import { validateSignatureAgent } from '../api/directory';

interface TestCase {
  name: string;
  signatureAgent: string;
  shouldPass: boolean;
  expectedErrorSubstring?: string;
}

const testCases: TestCase[] = [
  // Valid cases
  {
    name: 'Valid HTTPS root domain',
    signatureAgent: 'https://example.com',
    shouldPass: true,
  },
  {
    name: 'Valid HTTPS subdomain',
    signatureAgent: 'https://api.example.com',
    shouldPass: true,
  },
  {
    name: 'Valid localhost with HTTP (for testing)',
    signatureAgent: 'http://localhost:3000',
    shouldPass: true,
  },
  {
    name: 'Valid localhost with HTTPS',
    signatureAgent: 'https://localhost:3000',
    shouldPass: true,
  },
  {
    name: 'Valid 127.0.0.1 with HTTP',
    signatureAgent: 'http://127.0.0.1:3000',
    shouldPass: true,
  },
  
  // Invalid cases - protocol issues
  {
    name: 'Invalid HTTP protocol (not localhost)',
    signatureAgent: 'http://example.com',
    shouldPass: false,
    expectedErrorSubstring: 'HTTPS protocol',
  },
  {
    name: 'Invalid FTP protocol',
    signatureAgent: 'ftp://example.com',
    shouldPass: false,
    expectedErrorSubstring: 'HTTPS protocol',
  },
  {
    name: 'No protocol',
    signatureAgent: 'example.com',
    shouldPass: false,
    expectedErrorSubstring: 'valid URL',
  },
  
  // Invalid cases - path/query/fragment
  {
    name: 'Contains path',
    signatureAgent: 'https://example.com/api',
    shouldPass: false,
    expectedErrorSubstring: 'root domain without path',
  },
  {
    name: 'Contains query parameters',
    signatureAgent: 'https://example.com?param=value',
    shouldPass: false,
    expectedErrorSubstring: 'query parameters or fragments',
  },
  {
    name: 'Contains fragment',
    signatureAgent: 'https://example.com#section',
    shouldPass: false,
    expectedErrorSubstring: 'query parameters or fragments',
  },
  {
    name: 'Contains path and query',
    signatureAgent: 'https://example.com/path?query=1',
    shouldPass: false,
    expectedErrorSubstring: 'root domain without path',
  },
  
  // Invalid cases - port specification (not allowed except localhost)
  {
    name: 'Contains explicit port (not localhost)',
    signatureAgent: 'https://example.com:8443',
    shouldPass: false,
    expectedErrorSubstring: 'must not specify a port',
  },
  
  // Invalid cases - malformed
  {
    name: 'Invalid URL format',
    signatureAgent: 'not-a-url',
    shouldPass: false,
    expectedErrorSubstring: 'valid URL',
  },
];

function runTests() {
  console.log('Testing Signature-Agent Header Validation (Unit Tests)\n');
  console.log('='.repeat(80));

  let passed = 0;
  let failed = 0;

  for (const testCase of testCases) {
    const result = validateSignatureAgent(testCase.signatureAgent);

    const testPassed = result.isValid === testCase.shouldPass;

    if (testPassed) {
      console.log(`✓ ${testCase.name}`);
      if (!result.isValid && result.error) {
        console.log(`  Error: ${result.error}`);
      }
      passed++;
    } else {
      console.log(`✗ ${testCase.name}`);
      console.log(`  Expected: ${testCase.shouldPass ? 'PASS' : 'FAIL'}`);
      console.log(`  Got: ${result.isValid ? 'PASS' : 'FAIL'}`);
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
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
  const results = runTests();
  process.exit(results.failed === 0 ? 0 : 1);
}

export { runTests, testCases };
