import { errors, importX509, JWK, jwtVerify } from 'jose';
import decode from './decode';
import {
  JwksNoMatchingKeyError,
  JwtCognitoClaimValidationError,
  JwtInvalidError,
  JwtVerificationError,
} from './errors';

function handleVerificationError(e: Error) {
  console.error(JSON.stringify({ JwtVerificationError: e }));
  if (
    e instanceof errors.JOSEError &&
    ['ERR_JWT_CLAIM_INVALID', 'ERR_JWT_EXPIRED', 'ERR_JWT_MALFORMED'].includes(e.code)
  ) {
    throw new JwtVerificationError(e);
  }

  if (isNoMatchingKeyError(e)) {
    throw new JwksNoMatchingKeyError(e);
  }

  throw e;
}

function isNoMatchingKeyError(e: Error) {
  return e instanceof errors.JOSEError && e.code === 'ERR_JWKS_NO_MATCHING_KEY';
}

export async function getKeyByKid(iss: string, kid: string) {
  const jwksEndpoint = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
  const result = await fetch(jwksEndpoint, {
    cf: {
      cacheEverything: true,
      cacheTtlByStatus: {
        '200-299': 18473,
        404: 1,
        '500-599': 0,
      },
    },
  });
  const keys = (await result.json()) as {
    [kid: string]: string;
  };

  return keys[kid];
}

export function getJwt(str: string) {
  if (!str || str.substring(0, 6) !== 'Bearer') {
    return null;
  }
  return str.substring(6).trim();
}

export function getVerifier(firebaseProjectId: string) {
  if (!crypto || !crypto.subtle) throw new Error('Crypto not supported, are you deploying to Cloudflare Worker?');
  return {
    verify: async (authHeader: string) => {
      const token = getJwt(authHeader);
      if (!token) throw new JwtInvalidError();
      const { header, payload } = decode(token);
      const { kid } = header;

      if (!payload.iss || !kid) throw new JwtInvalidError();
      const keyString = await getKeyByKid(payload.iss, kid);

      try {
        const joseOptions = {
          profile: 'id',
          audience: firebaseProjectId,
          issuer: `https://securetoken.google.com/${firebaseProjectId}`,
        };
        const key = await importX509(keyString, 'RS256');
        return await jwtVerify(token, key, joseOptions);
      } catch (e) {
        handleVerificationError(e as Error);
      }
    },
  };
}

export function isJwtError(e: Error) {
  if (
    e instanceof JwksNoMatchingKeyError ||
    e instanceof JwtVerificationError ||
    e instanceof JwtInvalidError ||
    e instanceof JwtCognitoClaimValidationError
  ) {
    return true;
  }
  return false;
}

export {
  JwtCognitoClaimValidationError,
  JwtVerificationError,
  JwksNoMatchingKeyError,
  JwtInvalidError,
} from './errors';
export * as decode from './decode';
export type { JWK, JWTPayload, JWTVerifyResult } from 'jose';
