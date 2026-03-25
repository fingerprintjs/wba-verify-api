/**
 * Unit tests for directory response Content-Type validation + fetch integration.
 *
 * Run with: npm run test:directory-content-type
 */

import * as http from 'http';
import type { AddressInfo } from 'net';
import {
  validateDirectoryResponseContentType,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON,
  fetchSignaturesDirectory,
  clearDirectoryCache,
} from '../api/directory';

interface Case {
  name: string;
  header: string | null;
  expectOk: boolean;
  errorSubstring?: string;
}

const cases: Case[] = [
  {
    name: 'Exact media type',
    header: HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON,
    expectOk: true,
  },
  {
    name: 'With charset=utf-8',
    header: `${HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON}; charset=utf-8`,
    expectOk: true,
  },
  {
    name: 'Case-insensitive media type',
    header: 'Application/Http-Message-Signatures-Directory+Json',
    expectOk: true,
  },
  {
    name: 'With charset and extra whitespace',
    header: `  ${HTTP_MESSAGE_SIGNATURES_DIRECTORY_JSON}  ;  charset=utf-8  `,
    expectOk: true,
  },
  {
    name: 'Reject application/json',
    header: 'application/json',
    expectOk: false,
    errorSubstring: 'Invalid Content-Type',
  },
  {
    name: 'Reject application/json with charset',
    header: 'application/json; charset=utf-8',
    expectOk: false,
    errorSubstring: 'Invalid Content-Type',
  },
  {
    name: 'Reject missing header',
    header: null,
    expectOk: false,
    errorSubstring: 'Missing Content-Type',
  },
  {
    name: 'Reject empty header',
    header: '   ',
    expectOk: false,
    errorSubstring: 'Missing Content-Type',
  },
  {
    name: 'Reject text/plain',
    header: 'text/plain',
    expectOk: false,
    errorSubstring: 'Invalid Content-Type',
  },
];

function runTests() {
  console.log('Directory Content-Type validation (unit tests)\n');
  console.log('='.repeat(80));

  let passed = 0;
  let failed = 0;

  for (const c of cases) {
    const r = validateDirectoryResponseContentType(c.header);
    const ok = (r.ok === true && c.expectOk) || (r.ok === false && !c.expectOk);
    const sub =
      !c.errorSubstring ||
      (!r.ok && r.error.toLowerCase().includes(c.errorSubstring.toLowerCase()));

    if (ok && (!c.expectOk ? sub : true)) {
      console.log(`✓ ${c.name}`);
      passed++;
    } else {
      console.log(`✗ ${c.name}`);
      console.log(`  expected ok=${c.expectOk}, got ${JSON.stringify(r)}`);
      failed++;
    }
  }

  console.log('\n' + '='.repeat(80));
  console.log(`\nResults: ${passed} passed, ${failed} failed (${cases.length} total)\n`);
  return { passed, failed, total: cases.length };
}

/**
 * Integration: fetchSignaturesDirectory fails with INVALID_DIRECTORY_CONTENT_TYPE when server sends application/json.
 */
function runFetchIntegrationTest(): Promise<boolean> {
  clearDirectoryCache();
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end('{}');
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      const url = `http://127.0.0.1:${addr.port}/.well-known/http-message-signatures-directory`;
      fetchSignaturesDirectory(url, 0)
        .then((result) => {
          const ok =
            result.success === false &&
            result.errorCode === 'INVALID_DIRECTORY_CONTENT_TYPE' &&
            Boolean(result.error?.includes('Invalid Content-Type'));
          server.close(() => resolve(ok));
        })
        .catch(() => {
          server.close(() => resolve(false));
        });
    });
  });
}

if (require.main === module) {
  const r = runTests();
  if (r.failed > 0) {
    process.exit(1);
  }
  runFetchIntegrationTest().then((ok) => {
    if (ok) {
      console.log('✓ fetchSignaturesDirectory rejects wrong Content-Type (integration)');
      process.exit(0);
    }
    console.log('✗ fetchSignaturesDirectory rejects wrong Content-Type (integration)');
    process.exit(1);
  });
}

export { runTests, cases, runFetchIntegrationTest };
