/**
 * Valid web-bot-auth Signature-Input strings for integration tests.
 */
import { WEB_BOT_AUTH_SIGNATURE_TAG } from '../api/signature-input';

export function webBotAuthSignatureInput(params: {
  createdSec: number;
  expiresSec: number;
  keyid: string;
  alg?: string;
  nonce?: string;
  tag?: string;
}): string {
  const alg = params.alg ?? 'ed25519';
  const nonce = params.nonce ?? 'Mj311bOYjyItNPeGy0GYLA==';
  const tag = params.tag ?? WEB_BOT_AUTH_SIGNATURE_TAG;
  return `sig1=("@authority" "signature-agent");created=${params.createdSec};expires=${params.expiresSec};keyid="${params.keyid}";alg="${alg}";nonce="${nonce}";tag="${tag}"`;
}
