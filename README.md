# cloudflare-firebase-jwt-verifier
A lightweight JWT verifier for Firebase Auth running on Cloudflare Workers.
This lib fetches, caches keys from Firebase, and verifies the JWT token.


## Why
Cloudflare Workers runtime doesn't support Node.js core modules, which means we cannot use common libs like `jsonwebtoken`.

## Install
```shell
npm i --save cloudflare-firebase-jwt-verifier
```
```shell
yarn add cloudflare-firebase-jwt-verifier
```
## Usage
```javascript
import { getVerifier, JwtInvalidError } from 'cloudflare-firebase-jwt-verifier';

const { verify } = getVerifier(firebaseProjectId);

export async function verifyAuth(request: Request) {
  const header = request.headers.get('Authorization');
  if (!header) {
    throw new JwtInvalidError();
  }
  return await verify(header);
}

addEventListener('fetch', (event) => {
  event.passThroughOnException();
  event.respondWith(async (event) => {
    const auth = await verifyAuth(request);
    const userId = auth?.payload.sub;
    return new Response({});
  });
});
```
