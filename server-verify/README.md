# Web Bot Auth Verification

A Web Bot Authentication (WBA) verification implementation using Vercel Functions and the Cloudflare `web-bot-auth` package. Built with vanilla TypeScript.

## Overview

This project demonstrates cryptographic verification of Web Bot Authentication requests following [RFC 9421 HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421) and the [Cloudflare Web Bot Auth specification](https://github.com/cloudflare/web-bot-auth).

Features:
- Real cryptographic signature verification using Ed25519 algorithm
- Trust-on-first-use validation with automatic key directory fetching
- RFC 9421 test keys for immediate testing
- Vercel serverless functions for verification
- Vanilla TypeScript/HTML frontend
- Comprehensive test suite

## Features

- **Trust-on-First-Use Validation**: Automatically fetches and caches public key directories
- **Signature-Agent Support**: Extracts directory URL from `signature-agent` header
- **Automatic Key Discovery**: Fetches public keys from `.well-known/http-message-signatures-directory`
- **Real Cryptographic Verification**: Uses Ed25519 for signature validation
- **1-hour Key Caching**: Optimized performance with intelligent caching

## Quick Start

### Prerequisites

- Node.js 18+
- Vercel CLI: `npm install -g vercel`

### Installation

```bash
npm install
```

### Run Locally

```bash
vercel dev
```

Server starts at `http://localhost:3000`

## Testing

### Running all tests

```bash
npm run test
```

The test suite validates both the main `/api/verify` endpoint and error handling. A mock directory endpoint at `/.well-known/http-message-signatures-directory` serves RFC 9421 test keys for local testing.

### Test with valid signatures (recommended)

```bash
npm run test:signed
```

This creates properly signed requests using the RFC 9421 Ed25519 test key and verifies them against the `/api/verify` endpoint. The test includes the `Signature-Agent` header pointing to the test server.


## How It Works

### HTTP Message Signatures

Web Bot Auth uses HTTP Message Signatures (RFC 9421), not custom headers. Valid requests require:

- `Signature` header: Contains the cryptographic signature
- `Signature-Agent` header: Contains the domain of the public key location
- `Signature-Input` header: Contains signature metadata (keyid, created, expires, etc.)

### Verification Flow

1. Extract `Signature`, `Signature-Input`, and `Signature-Agent` headers
2. Extract public key directory URL from `Signature-Agent` header
3. Fetch public key directory with caching (1-hour TTL)
4. Parse `keyid` from `Signature-Input` and find matching key in the key directory JSON
5. Verify signature using `web-bot-auth` package with fetched key
6. Return success (200) or error (400)


## API Reference

### Endpoint: `GET /api/verify`

Modern verification endpoint with trust-on-first-use validation and automatic key directory fetching.

**Required Headers:**
- `Signature`: The HTTP Message Signature
- `Signature-Input`: Signature metadata (keyid, created, expires, etc.)
- `Signature-Agent`: Domain to fetch the public key directory from

**Success Response (200)**

```json
{
  "status": "success",
  "details": {
    "method": "GET",
    "url": "/api/verify",
    "headers": {
      "signature": "sig1=:...",
      "signature-agent": "\"https://example-ai-agent.com\"",
      "signature-input": "sig1=(...)..."
    },
    "timestamp": "2025-10-28T15:43:21.324Z",
    "keyId": "test-key-ed25519",
    "keySource": "directory: https://example-ai-agent/.well-known/http-message-signatures-directory"
  }
}
```

**Error Response (400)**

```json
{
  "status": "error",
  "errors": [
    {
      "code": "MISSING_SIGNATURE_HEADERS",
      "message": "Required headers `Signature`, `Signature-Input`, and `Signature-Agent` are missing"
    }
  ]
}
```

### Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `MISSING_SIGNATURE_HEADERS` | 400 | Missing required signature headers (except when only `Signature-Agent` is missing; see `MISSING_SIGNATURE_AGENT`) |
| `MISSING_SIGNATURE_AGENT` | 400 | `Signature` and `Signature-Input` are present but `Signature-Agent` is missing |
| `INVALID_SIGNATURE_AGENT` | 400 | Signature-Agent header is malformed or invalid (must be HTTPS root domain) |
| `INVALID_SIGNATURE_INPUT` | 400 | `Signature-Input` does not match the web-bot-auth profile (any `label=(...);...` before parameters; quoted covered components `@authority` and `signature-agent`; `tag="web-bot-auth"`; `alg="ed25519"`; quoted `keyid`/`nonce`; unquoted `created`/`expires`, etc.) |
| `SIGNATURE_EXPIRED` | 400 | Signature has expired (current time is past the `expires` parameter) |
| `SIGNATURE_TOO_OLD` | 400 | Signature created timestamp is too old (created more than 1 hour ago) |
| `SIGNATURE_TIMESTAMP_FUTURE` | 400 | Signature created timestamp is too far in the future (more than 5 minutes ahead) |
| `KEY_DIRECTORY_FETCH_FAILED` | 400 | Failed to fetch key directory from signature-agent URL |
| `INVALID_DIRECTORY_CONTENT_TYPE` | 400 | Directory response must use `Content-Type: application/http-message-signatures-directory+json` (parameters such as `charset` are allowed) |
| `KEY_EXPIRED` | 400 | JWK has expired (current time is past the key's `exp` field) |
| `KEY_NOT_YET_VALID` | 400 | JWK is not yet valid (current time is before the key's `nbf` field) |
| `KEY_NOT_FOUND` | 400 | No matching key found in directory for the provided `keyid` |
| `VERIFICATION_FAILED` | 400 | Cryptographic signature verification failed |
| `VALIDATION_FAILED` | 400 | Generic validation failure (e.g. malformed `created`/`expires` in `Signature-Input`, purpose mismatch, or unexpected server-side error) |
| `INTERNAL_ERROR` | 500 | Internal server error |

## License

MIT