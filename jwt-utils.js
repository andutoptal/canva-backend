import { JwksClient } from "jwks-rsa";
import jwt from "jsonwebtoken";

const CACHE_EXPIRY_MS = 60 * 60 * 1_000; // 60 minutes
const TIMEOUT_MS = 30 * 1_000; // 30 seconds

export async function getActivePublicKey({
  appId,
  token,
  cacheExpiryMs = CACHE_EXPIRY_MS,
  timeoutMs = TIMEOUT_MS,
}) {
  const decoded = jwt.decode(token, {
    complete: true,
  });

  const { kid } = decoded.header;

  const jwks = new JwksClient({
    cache: true,
    cacheMaxAge: cacheExpiryMs,
    timeout: timeoutMs,
    rateLimit: true,
    jwksUri: `https://api.canva.com/rest/v1/apps/${appId}/jwks`,
  });

  const key = await jwks.getSigningKey(kid);
  return key.getPublicKey();
}
