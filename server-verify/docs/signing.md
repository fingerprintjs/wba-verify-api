## Creating Signed Requests

```typescript
import { signatureHeaders } from 'web-bot-auth';
import { signerFromJWK } from 'web-bot-auth/crypto';

// Create signer with private key
const signer = await signerFromJWK(privateKey);

// Generate signature headers
const now = new Date();
const headers = await signatureHeaders(request, signer, {
  created: now,
  expires: new Date(now.getTime() + 300000) // 5 minutes
});

// Use headers in request
fetch(url, {
  headers: {
    'Signature': headers['Signature'],
    'Signature-Input': headers['Signature-Input'],
    'Signature-Agent': 'https://your-domain.com'
  }
});
```