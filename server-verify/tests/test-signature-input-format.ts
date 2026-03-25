/**
 * Unit tests for Signature-Input format validation (web-bot-auth profile).
 *
 * Run with: npm run test:signature-input
 */

import {
  validateSignatureInputFormat,
  WEB_BOT_AUTH_SIGNATURE_TAG,
} from '../api/signature-input';

interface Case {
  name: string;
  signatureInput: string;
  expectValid: boolean;
  errorSubstring?: string;
}

const nowSec = Math.floor(Date.now() / 1000);

const validBase =
  `sig1=("@authority" "signature-agent");created=${nowSec};expires=${nowSec + 300};` +
  `keyid="KYG4GtgVVPWw3r1AXgM6fYFw5kAvRZiJVxZY1Rsgc3Q";alg="ed25519";nonce="Mj311bOYjyItNPeGy0GYLA==";tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`;

const cases: Case[] = [
  {
    name: 'Valid full example (quoted covered components, tag web-bot-auth)',
    signatureInput: validBase,
    expectValid: true,
  },
  {
    name: 'Valid: covered component order reversed',
    signatureInput: validBase.replace(
      '("@authority" "signature-agent")',
      '("signature-agent" "@authority")'
    ),
    expectValid: true,
  },
  {
    name: 'Valid: arbitrary label (foo) instead of sig1',
    signatureInput: validBase.replace(/^sig1=/, 'foo='),
    expectValid: true,
  },
  {
    name: 'Valid: arbitrary label with hyphen and digit',
    signatureInput: validBase.replace(/^sig1=/, 'my-key_2='),
    expectValid: true,
  },
  {
    name: 'Invalid: empty covered components',
    signatureInput: `sig1=();created=${nowSec};expires=${nowSec + 300};keyid="kid";alg="ed25519";nonce="n";tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
    expectValid: false,
    errorSubstring: '@authority',
  },
  {
    name: 'Invalid: missing signature-agent covered component',
    signatureInput: `sig1=("@authority");created=${nowSec};expires=${nowSec + 300};keyid="kid";alg="ed25519";nonce="n";tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
    expectValid: false,
    errorSubstring: 'signature-agent',
  },
  {
    name: 'Invalid: unquoted @authority in covered list',
    signatureInput: `sig1=(@authority "signature-agent");created=${nowSec};expires=${nowSec + 300};keyid="kid";alg="ed25519";nonce="n";tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
    expectValid: false,
    errorSubstring: 'double-quoted',
  },
  {
    name: 'Invalid: tag is not web-bot-auth',
    signatureInput: validBase.replace(`tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`, 'tag="other-tag"'),
    expectValid: false,
    errorSubstring: 'tag',
  },
  {
    name: 'Invalid: tag unquoted',
    signatureInput: validBase.replace(
      `tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
      `tag=${WEB_BOT_AUTH_SIGNATURE_TAG}`
    ),
    expectValid: false,
    errorSubstring: 'tag',
  },
  {
    name: 'Invalid: keyid unquoted',
    signatureInput: validBase.replace(
      'keyid="KYG4GtgVVPWw3r1AXgM6fYFw5kAvRZiJVxZY1Rsgc3Q"',
      'keyid=KYG4GtgVVPWw3r1AXgM6fYFw5kAvRZiJVxZY1Rsgc3Q'
    ),
    expectValid: false,
    errorSubstring: 'keyid',
  },
  {
    name: 'Invalid: alg unquoted',
    signatureInput: validBase.replace('alg="ed25519"', 'alg=ed25519'),
    expectValid: false,
    errorSubstring: 'alg',
  },
  {
    name: 'Invalid: alg wrong value',
    signatureInput: validBase.replace('alg="ed25519"', 'alg="ES256"'),
    expectValid: false,
    errorSubstring: 'ed25519',
  },
  {
    name: 'Invalid: created is quoted',
    signatureInput: validBase.replace(`created=${nowSec}`, `created="${nowSec}"`),
    expectValid: false,
    errorSubstring: 'created',
  },
  {
    name: 'Invalid: nonce empty',
    signatureInput: validBase.replace('nonce="Mj311bOYjyItNPeGy0GYLA=="', 'nonce=""'),
    expectValid: false,
    errorSubstring: 'nonce',
  },
  {
    name: 'Invalid: missing nonce parameter',
    signatureInput: validBase.replace(/;nonce="[^"]*"/, ''),
    expectValid: false,
    errorSubstring: 'nonce',
  },
  {
    name: 'Invalid: malformed (no parentheses)',
    signatureInput: `sig1="@authority";created=${nowSec}`,
    expectValid: false,
    errorSubstring: 'label=(',
  },
  {
    name: 'Invalid: missing equals between label and covered list',
    signatureInput: validBase.replace(/^sig1=\(/, 'sig1('),
    expectValid: false,
    errorSubstring: 'label=(',
  },
  {
    name: 'Valid: nonce value contains = (base64 padding) inside quotes',
    signatureInput:
      `sig1=("@authority" "signature-agent");created=${nowSec};expires=${nowSec + 300};` +
      `keyid="kid";alg="ed25519";nonce="abc=def==";tag="${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
    expectValid: true,
  },
];

function runUnitTests() {
  console.log('Signature-Input format validation (unit tests)\n');
  console.log('='.repeat(80));

  let passed = 0;
  let failed = 0;

  for (const c of cases) {
    const r = validateSignatureInputFormat(c.signatureInput);
    const ok = r.isValid === c.expectValid;
    const subOk =
      !c.errorSubstring ||
      !r.error ||
      r.error.toLowerCase().includes(c.errorSubstring.toLowerCase());

    if (ok && (!c.expectValid ? subOk : true)) {
      console.log(`✓ ${c.name}`);
      passed++;
    } else {
      console.log(`✗ ${c.name}`);
      console.log(`  expected valid=${c.expectValid}, got ${r.isValid}`);
      if (r.error) console.log(`  error: ${r.error}`);
      failed++;
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(`\nResults: ${passed} passed, ${failed} failed (${cases.length} total)\n`);
  return { passed, failed, total: cases.length };
}

if (require.main === module) {
  const r = runUnitTests();
  process.exit(r.failed === 0 ? 0 : 1);
}

export { runUnitTests, cases };
