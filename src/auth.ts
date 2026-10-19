import { createHash, timingSafeEqual } from "crypto";
import { type NextFunction, type Request, type Response } from "express";
import * as jose from "jose";
import { UnauthorizedError } from "./errors";

const ALLOWED_IDENTITIES = process.env.ALLOWED_IDENTITIES?.split(",")
    .map((identity) => identity.trim().toLowerCase())
    .filter(Boolean);

const getAllowedIdentities = () => {
  if (!ALLOWED_IDENTITIES) return null;
  return ALLOWED_IDENTITIES.length > 0 ? new Set(ALLOWED_IDENTITIES) : null;
};

export const isIdentityAllowed = (identity?: string | null) => {
  const allowedIdentities = getAllowedIdentities();
  const identityNormalized = identity?.trim().toLowerCase();
  if (!allowedIdentities) return true;
  if (!identityNormalized) return false;
  return allowedIdentities.has(identityNormalized);
};

/**
 * Identity provider.
 *
 * Upstream signs users in with Google. When OIDC_ISSUER is set (e.g.
 * https://login.microsoftonline.com/<tenant>/v2.0) the API uses that OpenID Connect
 * provider instead — Microsoft Entra ID in the branded deployment. Without
 * OIDC_ISSUER everything behaves exactly as upstream.
 */
export const GOOGLE_ISSUER = "https://accounts.google.com";

export const isCustomOidc = () => !!process.env.OIDC_ISSUER;
export const oidcIssuer = () => process.env.OIDC_ISSUER || GOOGLE_ISSUER;
export const oidcClientId = () =>
  (isCustomOidc() ? process.env.OIDC_CLIENT_ID : process.env.GOOGLE_CLIENT_ID) as string;
export const oidcClientSecret = () =>
  (isCustomOidc() ? process.env.OIDC_CLIENT_SECRET : process.env.GOOGLE_CLIENT_SECRET) as string;

/** True when a token was issued by the identity provider this API uses. */
export const isTrustedIssuer = (iss?: string | null) => !!iss && iss === oidcIssuer();

/** Signing keys of the provider: Google's certs, Entra's v2.0 keys, or OIDC_JWKS_URI. */
export const jwksUriFor = (issuer: string) => {
  if (process.env.OIDC_JWKS_URI) return process.env.OIDC_JWKS_URI;
  if (issuer === GOOGLE_ISSUER) return "https://www.googleapis.com/oauth2/v3/certs";
  // https://login.microsoftonline.com/<tenant>/v2.0 -> .../<tenant>/discovery/v2.0/keys
  return issuer.replace(/\/v2\.0\/?$/, "") + "/discovery/v2.0/keys";
};

// One key set per issuer for the life of the process (jose caches and refreshes the keys).
const jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();
const jwksFor = (issuer: string) => {
  let jwks = jwksCache.get(issuer);
  if (!jwks) {
    jwks = jose.createRemoteJWKSet(new URL(jwksUriFor(issuer)));
    jwksCache.set(issuer, jwks);
  }
  return jwks;
};

/** App roles that may use the portal (Entra only). Override with OIDC_ALLOWED_ROLES="A,B". */
export const allowedRoles = () =>
  (process.env.OIDC_ALLOWED_ROLES ?? "KVM.ProviderAdmin,KVM.Operator,KVM.Viewer")
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);

/** E-mail used for ALLOWED_IDENTITIES: Google sends `email`; Entra often only `preferred_username`. */
export const identityEmail = (claims: Record<string, unknown>) => {
  for (const key of ["email", "preferred_username", "upn"]) {
    const value = claims[key];
    if (typeof value === "string" && value.includes("@")) return value;
  }
  return undefined;
};

/**
 * Extra checks for a custom (Entra) provider: the token must come from our tenant and carry
 * one of the KVM app roles. Returns an error code, or null when the claims are acceptable.
 */
export const checkProviderClaims = (claims: Record<string, unknown>): string | null => {
  if (!isCustomOidc()) return null;
  const tenant = process.env.OIDC_TENANT_ID;
  if (tenant && claims.tid !== tenant) return "wrong_tenant";
  const roles = Array.isArray(claims.roles) ? (claims.roles as unknown[]) : [];
  const allowed = allowedRoles();
  if (allowed.length > 0 && !roles.some((r) => typeof r === "string" && allowed.includes(r))) {
    return "missing_app_role";
  }
  return null;
};

export const verifyToken = async (idToken: string) => {
  const issuer = oidcIssuer();
  try {
    const { payload } = await jose.jwtVerify(idToken, jwksFor(issuer), {
      issuer,
      audience: oidcClientId(),
    });

    return payload;
  } catch  (e) {
    console.error(e);
    return null;
  }
};

export const authenticated = async (req: Request, res: Response, next: NextFunction) => {
  const idToken = req.session?.id_token;
  if (!idToken) throw new UnauthorizedError();

  const payload = await verifyToken(idToken);
  if (!payload) throw new UnauthorizedError();
  if (!payload.exp) throw new UnauthorizedError();

  if (new Date(payload.exp * 1000) < new Date()) {
    throw new UnauthorizedError();
  }

  const claimError = checkProviderClaims(payload);
  if (claimError) throw new UnauthorizedError("Account is not authorized for this portal", claimError);

  const email = identityEmail(payload);
  if (!isIdentityAllowed(email)) {
    throw new UnauthorizedError("Account is not in the allowlist", "account_not_allowed");
  }

  next();
};

const sha256 = (value: string) => createHash("sha256").update(value).digest();

/** Guards a route with one static bearer token, compared in constant time. */
export const bearerToken = (expected: string) => {
  const expectedDigest = sha256(expected);
  return (req: Request, res: Response, next: NextFunction) => {
    // The scheme name is case-insensitive (RFC 9110); the token is not.
    const presented = req.headers.authorization?.match(/^Bearer +(.+)$/i)?.[1];
    if (!presented || !timingSafeEqual(sha256(presented), expectedDigest)) {
      throw new UnauthorizedError("Invalid bearer token");
    }
    next();
  };
};
