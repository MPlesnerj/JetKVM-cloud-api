import { BaseClient, generators, Issuer } from "openid-client";
import express from "express";
import { prisma } from "./db";
import { BadRequestError, UnauthorizedError } from "./errors";
import {
  checkProviderClaims,
  identityEmail,
  isCustomOidc,
  isIdentityAllowed,
  oidcClientId,
  oidcClientSecret,
  oidcIssuer,
} from "./auth";
import * as crypto from "crypto";

const API_HOSTNAME = process.env.API_HOSTNAME;
const APP_HOSTNAME = process.env.APP_HOSTNAME;
const REDIRECT_URI = process.env.OIDC_REDIRECT_URI || `${API_HOSTNAME}/oidc/callback`;

// Google upstream; Entra ID (or another OIDC provider) when OIDC_ISSUER is set — see auth.ts.
// The provider's discovery document is fetched once per process instead of on every login.
let clientPromise: Promise<BaseClient> | null = null;
const getGoogleOIDCClient = (): Promise<BaseClient> => {
  if (!clientPromise) {
    clientPromise = Issuer.discover(oidcIssuer())
      .then(
        (issuer) =>
          new issuer.Client({
            client_id: oidcClientId(),
            client_secret: oidcClientSecret(),
            redirect_uris: [REDIRECT_URI],
            response_types: ["code"],
          }),
      )
      .catch((err) => {
        clientPromise = null; // try discovery again on the next login
        throw err;
      });
  }
  return clientPromise;
};

export const Google = async (req: express.Request, res: express.Response) => {
  const state = new URLSearchParams();

  // Generate a CSRF token and store it in the session, so the callback
  // can ensure that the request is the same as the one that was initiated.
  state.set("csrf", generators.state());
  req.session!.csrf = state.get("csrf");

  req.session!.deviceId = req.body.deviceId;
  req.session!.returnTo = req.body.returnTo;

  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  req.session!.code_verifier = code_verifier;

  const client = await getGoogleOIDCClient();
  const authorizationUrl = client.authorizationUrl({
    scope: "openid email profile",
    state: state.toString(),
    // This ensures that to even issue the token, the client must have the code_verifier,
    // which is stored in the session cookie.
    code_challenge,
    code_challenge_method: "S256",
    // Entra: always show the account picker (users often have several work accounts)
    ...(isCustomOidc() ? { prompt: "select_account" } : {}),
  });
  return res.redirect(authorizationUrl);
};

export const Callback = async (req: express.Request, res: express.Response) => {
  const client = await getGoogleOIDCClient();

  // Retrieve recognized callback parameters from the request, e.g. code and state
  const params = client.callbackParams(req);
  if (!params)
    throw new BadRequestError("Missing callback parameters", "missing_callback_params");

  // The provider reports refused sign-ins (e.g. user not assigned to the Entra app) as error params.
  if (params.error) {
    console.warn("Sign-in refused by the identity provider:", params.error, params.error_description);
    throw new UnauthorizedError(
      params.error_description || "Sign-in was not completed",
      params.error === "access_denied" ? "account_not_allowed" : "sign_in_failed",
    );
  }

  const sessionCsrf = req.session?.csrf;
  if (!sessionCsrf) {
    throw new BadRequestError("Missing CSRF in session", "missing_csrf");
  }

  const thisRequestCsrf = new URLSearchParams(params.state).get("csrf");
  if (thisRequestCsrf !== sessionCsrf) {
    throw new BadRequestError("Invalid CSRF", "invalid_csrf");
  }

  const deviceId = req.session?.deviceId as string | undefined;
  const returnTo = (req.session?.returnTo ?? `${APP_HOSTNAME}/devices`) as string;

  req.session!.csrf = null;
  req.session!.returnTo = null;
  req.session!.deviceId = null;

  // Exchange code for access token and ID token
  const tokenSet = await client.callback(REDIRECT_URI, params, {
    state: req.query.state?.toString(),
    code_verifier: req.session?.code_verifier,
  });

  // TokenClaims is an object that contains the sub, email, name and other claims
  const tokenClaims = tokenSet.claims();
  if (!tokenClaims) {
    throw new BadRequestError("Missing claims in token", "missing_claims");
  }

  if (!tokenSet.id_token) {
    throw new BadRequestError("Missing ID Token", "missing_id_token");
  }

  // Google: e-mail and picture come from the userinfo endpoint.
  // Entra: everything needed is in the ID token (its userinfo endpoint lives on Microsoft Graph).
  const userInfo = isCustomOidc()
    ? { email: identityEmail(tokenClaims), picture: undefined as string | undefined }
    : await client.userinfo(tokenSet);

  const claimError = checkProviderClaims(tokenClaims);
  if (claimError) {
    req.session = null;
    console.warn("Sign-in rejected:", claimError, "sub", tokenClaims.sub);
    throw new UnauthorizedError("Account is not authorized for this portal", claimError);
  }

  if (!userInfo.email) {
    req.session = null;
    throw new BadRequestError("Missing email claim in user info", "missing_email_claim");
  }
  if (!isIdentityAllowed(userInfo.email)) {
    req.session = null;
    throw new UnauthorizedError("Account is not in the allowlist", "account_not_allowed");
  }

  req.session!.id_token = tokenSet.id_token;

  await prisma.user.upsert({
    where: { googleId: tokenClaims.sub },
    update: {
      googleId: tokenClaims.sub,
      email: userInfo.email,
      picture: userInfo.picture,
    },
    create: {
      googleId: tokenClaims.sub,
      email: userInfo.email,
      picture: userInfo.picture,
    },
  });

  // This means the user is trying to adopt a device by first logging/signin up/in
  if (deviceId) {
    const deviceAdopted = await prisma.device.findUnique({
      where: { id: deviceId },
      select: { user: { select: { googleId: true } } },
    });


    const isAdoptedByCurrentUser = deviceAdopted?.user.googleId === tokenClaims.sub;
    const isAdoptedByOther = deviceAdopted && !isAdoptedByCurrentUser;
    if (isAdoptedByOther) {
      // Device is already adopted by another user. This can happen if:
      // 1. The device was resold without being de-registered by the previous owner.
      // 2. Someone is trying to adopt a device they don't own.
      //
      // Security note:
      // The previous owner can't connect to the device anymore because:
      // - The device would have done a hardware reset, erasing its deviceToken.
      // - Without a valid deviceToken, the device can't connect to the cloud API.
      //
      // This check prevents unauthorized adoption and ensures proper ownership transfer.
      // The cost of this check is therefore, that the previous owner has to re-register the device.
      return res.redirect(`${APP_HOSTNAME}/already-adopted`);
    }

    // Temp Token expires in 5 minutes
    const tempToken = crypto.randomBytes(20).toString("hex");
    const tempTokenExpiresAt = new Date(new Date().getTime() + 5 * 60000);

    await prisma.user.update({
      where: { googleId: tokenClaims.sub },
      data: {
        device: {
          upsert: {
            create: { id: deviceId, tempToken, tempTokenExpiresAt },
            where: { id: deviceId },
            update: { tempToken, tempTokenExpiresAt },
          },
        },
      },
    });

    console.log("Adopted device", deviceId, "for user", tokenClaims.sub);

    const url = new URL(returnTo);
    url.searchParams.append("tempToken", tempToken);
    url.searchParams.append("deviceId", deviceId);
    // The device verifies this ID token itself. The parameter names stay as upstream so the
    // device UI forwards them unchanged; patched firmware learns the issuer from GET /oidc/config.
    url.searchParams.append("oidcGoogle", tokenSet.id_token.toString());
    url.searchParams.append("clientId", oidcClientId());
    return res.redirect(url.toString());
  }
  return res.redirect(returnTo);
};

/**
 * GET /oidc/config — which identity provider this cloud uses. Public, no secrets.
 * Patched device firmware reads it when it is adopted, so it can verify tokens from Entra ID.
 */
export const Config = async (req: express.Request, res: express.Response) => {
  return res.json({ issuer: oidcIssuer(), clientId: oidcClientId() });
};
