import { RequestEnv } from "@/middlewares/context_storage";
import { Hono } from "hono";
import { auth, authMiddleware } from "@/middlewares/auth";
import { errorResponse, successResponse } from "@/commons/utils/api_response";
import { zValidator } from "@hono/zod-validator";
import { getRecoveryCodesSchema } from "@/commons/validators/auth.validator";
import { validateErrorHook } from "@/commons/utils/app_error";
import { getUserWithPassword, resetRecoveryCodes } from "../auth/auth.service";
import { verify } from "@/commons/utils/hash";
import {
  decodeBase64,
  encodeBase32NoPadding,
  encodeBase32UpperCase,
  encodeBase64,
} from "@oslojs/encoding";
import StatusCodes from "http-status";
import { ErrorCode } from "@/commons/enums/error_code";
import { decrypt, encrypt, encryptString } from "@/commons/utils/encryption";
import { generateRandomRecoveryCode } from "@/commons/utils/code";

const app = new Hono<RequestEnv>();

app.get("/current", authMiddleware(true), async (c) => {
  const session = auth();
  return successResponse(c, { data: { user: session.user } });
});

app.post(
  "/recovery-codes",
  authMiddleware(),
  zValidator(
    "json",
    getRecoveryCodesSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    const { user } = auth();
    const { password } = c.req.valid("json");

    const { password_hash, password_salt } = await getUserWithPassword(
      user.email,
    );

    const isCorrectPassword = await verify(
      password,
      password_hash!,
      Buffer.from(decodeBase64(password_salt!)),
    );

    if (!isCorrectPassword) {
      return errorResponse(c, "incorrect password", StatusCodes.NOT_FOUND, {
        error_code: ErrorCode.INCORRECT_PASSWORD,
      });
    }

    let decryptedCodeBytes = user.preference.recovery_codes?.map((code) =>
      decrypt(decodeBase64(code)),
    );

    if (!decryptedCodeBytes) {
      decryptedCodeBytes = Array(5)
        .fill(0)
        .map(() => {
          const code = generateRandomRecoveryCode();
          return new TextEncoder().encode(code);
        });

      await resetRecoveryCodes(
        user.id,
        decryptedCodeBytes.map((byteSlice) => encodeBase64(encrypt(byteSlice))),
      );
    }

    const recoveryCodes = decryptedCodeBytes.map((byteSlice) =>
      encodeBase32NoPadding(byteSlice),
    );
    return successResponse(c, { data: { recoveryCodes } });
  },
);

app.post(
  "/recovery-codes/reset",
  authMiddleware(),
  zValidator(
    "json",
    getRecoveryCodesSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    const { user } = auth();
    const { password } = c.req.valid("json");

    const { password_hash, password_salt } = await getUserWithPassword(
      user.email,
    );

    const isCorrectPassword = await verify(
      password,
      password_hash!,
      Buffer.from(decodeBase64(password_salt!)),
    );

    if (!isCorrectPassword) {
      return errorResponse(c, "incorrect password", StatusCodes.NOT_FOUND, {
        error_code: ErrorCode.INCORRECT_PASSWORD,
      });
    }

    const encryptedRecoveryCodes = Array(5)
      .fill(0)
      .map(() => {
        const code = generateRandomRecoveryCode();
        return {
          encrypted: encodeBase64(encryptString(code)),
          encoded: encodeBase32UpperCase(new TextEncoder().encode(code)),
        };
      });

    await resetRecoveryCodes(
      user.id,
      encryptedRecoveryCodes.map((code) => code.encrypted),
    );

    const recoveryCodes = encryptedRecoveryCodes.map((code) => code.encoded);
    return successResponse(c, { data: { recoveryCodes } });
  },
);

export default app;
