import { errorResponse, successResponse } from "@/commons/utils/api_response";
import { generate2faSecret } from "@/commons/utils/code";
import { auth, authMiddleware } from "@/middlewares/auth";
import { RequestEnv } from "@/middlewares/context_storage";
import { Hono } from "hono";
import { createTOTPKeyURI, verifyTOTP } from "@oslojs/otp";
import { getEnv } from "config/env";
import { decrypt, encrypt } from "@/commons/utils/encryption";
import { decodeBase64, encodeBase64 } from "@oslojs/encoding";
import qrcode from "qrcode";
import StatusCodes from "http-status";
import { zValidator } from "@hono/zod-validator";
import {
  verifyLoginMfaSchema,
  verifyMfaSetupSchema,
} from "@/commons/validators/mfa.validator";
import { removeMfaSecret, setMfaSecret } from "./mfa.service";
import { validateErrorHook } from "@/commons/utils/app_error";
import { signToken } from "@/commons/utils/token";
import { JwtAccessPayload } from "@/commons/interface/jwt";
import { createDate } from "oslo";
import { markSessionAs2faVerified } from "../session/session.service";
import { setAuthenicationCookie } from "@/commons/utils/cookie";

const app = new Hono<RequestEnv>();

app.get("/setup", authMiddleware(true), async (c) => {
  const { user } = auth();

  if (user.preference.enabled_2fa) {
    return errorResponse(c, "Mfa already enabled");
  }

  let secret = user.preference.two_factor_secret
    ? decrypt(new TextEncoder().encode(user.preference.two_factor_secret))
    : null;

  let encodedKey: string, keyBytes: Uint8Array;

  if (secret) {
    [encodedKey, keyBytes] = [encodeBase64(secret), secret];
  } else {
    [encodedKey, keyBytes] = generate2faSecret();
  }

  const totpURI = createTOTPKeyURI(
    getEnv("PLATFORM_NAME"),
    user.name,
    keyBytes,
    30,
    6,
  );

  const qrImageUrl = await qrcode.toDataURL(totpURI);
  return successResponse(
    c,
    {
      data: {
        encodedKey,
        qrImageUrl,
      },
    },
    StatusCodes.OK,
    "Scan the QR code or use the setup key",
  );
});

app.post(
  "/confirm",
  authMiddleware(true),
  zValidator("json", verifyMfaSetupSchema),
  async (c) => {
    const { user, session } = auth();
    if (user.preference.enabled_2fa) {
      return errorResponse(c, "Mfa already enabled");
    }

    const { code, secret } = c.req.valid("json");
    const keyBytes = decodeBase64(secret);
    if (!verifyTOTP(keyBytes, 30, 6, code)) {
      return errorResponse(c, "Invalid code", StatusCodes.FORBIDDEN);
    }

    const encryptedByte = encrypt(keyBytes);
    const encryptedKey = encodeBase64(encryptedByte);

    await setMfaSecret(user.id, encryptedKey);
    await markSessionAs2faVerified(session.session_id, session.user_id);
    return successResponse(
      c,
      { data: { enabled2fa: true } },
      StatusCodes.OK,
      "mfa setup completed",
    );
  },
);

app.post(
  "/verify",
  authMiddleware(true),
  zValidator(
    "json",
    verifyLoginMfaSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    const { code } = c.req.valid("json");
    const { session, user } = auth();

    if (!(user.preference.enabled_2fa && user.preference.two_factor_secret)) {
      return errorResponse(c, "Mfa not setup", StatusCodes.FORBIDDEN);
    }

    const keyBytes = decrypt(decodeBase64(user.preference.two_factor_secret));

    if (!verifyTOTP(keyBytes, 30, 6, code)) {
      return errorResponse(c, "Invalid code", StatusCodes.FORBIDDEN);
    }

    await markSessionAs2faVerified(session.session_id, session.user_id);
    const accessToken = await signToken<JwtAccessPayload>(
      { ...session, required_2fa: true, two_factor_verified: true },
      getEnv("AUTH_SECRET"),
      getEnv("AUTH_EXPIRES_IN"),
    );

    setAuthenicationCookie(c, { access: accessToken });
    return successResponse(
      c,
      {
        data: {
          accessToken: {
            value: accessToken.token,
            expiredAt: createDate(accessToken.expiresIn),
          },
        },
      },
      StatusCodes.OK,
      "mfa verified and logged in",
    );
  },
);

app.post("/revoke", authMiddleware(), async (c) => {
  const { user } = auth();

  if (!user.preference.enabled_2fa) {
    return errorResponse(c, "mfa not setup");
  }

  await removeMfaSecret(user.id);

  return successResponse(
    c,
    { data: { mfaRequired: false } },
    StatusCodes.OK,
    "Mfa removed succesfully",
  );
});

export default app;
