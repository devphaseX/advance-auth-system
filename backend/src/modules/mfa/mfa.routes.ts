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
import { verifyMfaSetupSchema } from "@/commons/validators/mfa.validator";
import { setMfaSecret } from "./mfa.service";

const app = new Hono<RequestEnv>();

app.get("/setup", authMiddleware, async (c) => {
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
  authMiddleware,
  zValidator("json", verifyMfaSetupSchema),
  async (c) => {
    const { user } = auth();
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
    return successResponse(c, undefined, StatusCodes.OK, "mfa setup completed");
  },
);

export default app;
