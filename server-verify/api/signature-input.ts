/**
 * Signature-Input header validation for the web-bot-auth profile (RFC 9421).
 * Aligns with web-bot-auth: covered components @authority + signature-agent, tag=web-bot-auth, alg=ed25519.
 */

/** Must match web-bot-auth `HTTP_MESSAGE_SIGNAGURE_TAG` */
export const WEB_BOT_AUTH_SIGNATURE_TAG = 'web-bot-auth';

/** Covered HTTP message components required when signing with Signature-Agent (see web-bot-auth REQUEST_COMPONENTS) */
export const REQUIRED_COVERED_COMPONENTS = ['@authority', 'signature-agent'] as const;

const REQUIRED_PARAM_KEYS = ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag'] as const;

const ED25519_ALG = 'ed25519';

/**
 * Parses space-separated double-quoted tokens inside the covered-components parens.
 * Rejects unquoted tokens (e.g. bare @authority).
 */
function parseQuotedCoveredComponents(inner: string): string[] | null {
  const t = inner.trim();
  if (t === '') {
    return [];
  }
  const out: string[] = [];
  let i = 0;
  while (i < t.length) {
    while (i < t.length && /\s/.test(t[i]!)) {
      i++;
    }
    if (i >= t.length) {
      break;
    }
    if (t[i] !== '"') {
      return null;
    }
    const end = t.indexOf('"', i + 1);
    if (end === -1) {
      return null;
    }
    out.push(t.slice(i + 1, end));
    i = end + 1;
  }
  return out;
}

/**
 * Splits `;k=v;k2=v2` after the initial `;`, respecting double-quoted values.
 */
function splitSemicolonParams(rest: string): string[] {
  if (!rest || rest.trim() === '') {
    return [];
  }
  const s = rest.trim();
  if (!s.startsWith(';')) {
    return [];
  }
  const body = s.slice(1);
  const segments: string[] = [];
  let buf = '';
  let inQuote = false;
  for (let k = 0; k < body.length; k++) {
    const c = body[k]!;
    if (c === '"') {
      inQuote = !inQuote;
    }
    if (c === ';' && !inQuote) {
      segments.push(buf);
      buf = '';
    } else {
      buf += c;
    }
  }
  segments.push(buf);
  return segments.map((x) => x.trim()).filter(Boolean);
}

function parseParams(rest: string): Record<string, string> | null {
  const segments = splitSemicolonParams(rest);
  const params: Record<string, string> = {};
  for (const seg of segments) {
    const eq = seg.indexOf('=');
    if (eq === -1) {
      return null;
    }
    const key = seg.slice(0, eq).trim();
    const rawVal = seg.slice(eq + 1).trim();
    params[key] = rawVal;
  }
  return params;
}

function isQuotedStringParam(raw: string): boolean {
  return raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"');
}

function unquote(raw: string): string {
  if (isQuotedStringParam(raw)) {
    return raw.slice(1, -1);
  }
  return raw;
}

/** First signature label in Signature-Input: `label=(covered);params` (label may be any token, e.g. `sig1`, `foo`, for multi-key / multi-signature setups). */
const SIGNATURE_INPUT_ENTRY =
  /^([^\s=]+)\s*=\s*\(\s*([^)]*)\s*\)\s*(.*)$/;

/**
 * Validates Signature-Input for this verifier's web-bot-auth profile.
 * Accepts any non-empty label before `=` (RFC 9421 allows multiple signatures; labels pair with `Signature` header labels).
 */
export function validateSignatureInputFormat(signatureInput: string): { isValid: boolean; error?: string } {
  const s = signatureInput.trim();

  const top = SIGNATURE_INPUT_ENTRY.exec(s);
  if (!top) {
    return {
      isValid: false,
      error:
        'Signature-Input must start with `label=(...);...` (any label, e.g. `sig1` or `foo`) and covered components in parentheses',
    };
  }

  const inner = top[2] ?? '';
  const rest = top[3] ?? '';

  const covered = parseQuotedCoveredComponents(inner);
  if (covered === null) {
    return {
      isValid: false,
      error:
        'Covered components must be a space-separated list of double-quoted strings (e.g. `"@authority" "signature-agent"`)',
    };
  }

  const coveredSet = new Set(covered);
  for (const req of REQUIRED_COVERED_COMPONENTS) {
    if (!coveredSet.has(req)) {
      return {
        isValid: false,
        error: `Covered components must include "${req}" (with other required components: ${REQUIRED_COVERED_COMPONENTS.map((c) => `"${c}"`).join(' ')})`,
      };
    }
  }

  const params = parseParams(rest);
  if (params === null) {
    return { isValid: false, error: 'Invalid Signature-Input parameters after `)`' };
  }

  for (const key of REQUIRED_PARAM_KEYS) {
    if (params[key] === undefined) {
      return {
        isValid: false,
        error: `Missing required Signature-Input parameter: ${key}`,
      };
    }
  }

  const createdRaw = params['created']!;
  const expiresRaw = params['expires']!;
  if (isQuotedStringParam(createdRaw) || isQuotedStringParam(expiresRaw)) {
    return {
      isValid: false,
      error: 'Parameters `created` and `expires` must be unquoted integer Unix timestamps',
    };
  }
  if (!/^\d+$/.test(createdRaw) || !/^\d+$/.test(expiresRaw)) {
    return {
      isValid: false,
      error: '`created` and `expires` must be decimal integer Unix timestamps',
    };
  }

  for (const key of ['keyid', 'alg', 'nonce', 'tag'] as const) {
    const raw = params[key]!;
    if (!isQuotedStringParam(raw)) {
      return {
        isValid: false,
        error: `Parameter \`${key}\` must be a double-quoted string`,
      };
    }
  }

  const alg = unquote(params['alg']!);
  if (alg !== ED25519_ALG) {
    return {
      isValid: false,
      error: `Parameter \`alg\` must be "${ED25519_ALG}" for this verifier`,
    };
  }

  const tag = unquote(params['tag']!);
  if (tag !== WEB_BOT_AUTH_SIGNATURE_TAG) {
    return {
      isValid: false,
      error: `Parameter \`tag\` must be "${WEB_BOT_AUTH_SIGNATURE_TAG}"`,
    };
  }

  const nonce = unquote(params['nonce']!);
  if (nonce.length === 0) {
    return { isValid: false, error: 'Parameter `nonce` must not be empty' };
  }

  return { isValid: true };
}
