import { RequestEnv } from "@/middlewares/context_storage";
import { Hono } from "hono";
import { auth, authMiddleware } from "@/middlewares/auth";
import { errorResponse, successResponse } from "@/commons/utils/api_response";
import { zValidator } from "@hono/zod-validator";
import {
  confirmChangeEmailSchema,
  getRecoveryCodesSchema,
  requestChangeEmailSchema,
} from "@/commons/validators/auth.validator";
import { validateErrorHook } from "@/commons/utils/app_error";
import {
  getClientUserPayload,
  getUser,
  resetRecoveryCodes,
  updateUserEmail,
  updateUserPassword,
} from "../auth/auth.service";
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
import {
  createVerificationCode,
  getVerificationCode,
  getVerificationCodeAttemptWithin,
  invalidateVerificationCodes,
  removeVerificationCode,
} from "@/services/verification.service";
import { VerificationEnum } from "@/commons/enums/verification.enum";
import {
  REQUEST_CHANGE_EMAIL_ALLOWED_ATTEMPT_DURATION,
  REQUEST_CHANGE_EMAIL_ATTEMPT,
} from "@/commons/utils/constant";
import { sendMail } from "@/mailers/mailer";
import { requestChangeEmailTemplate } from "@/mailers/templates/template";
import { signToken } from "@/commons/utils/token";
import { getEnv } from "config/env";
import { JwtRequestEmailChangePayload } from "@/commons/interface/jwt";
import { isPast } from "date-fns";

const app = new Hono<RequestEnv>();

app.get("/current", authMiddleware(true), async (c) => {
  const session = auth();

  return successResponse(c, {
    data: { user: await getClientUserPayload({ id: session.user.id }) },
  });
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

    const { password_hash, password_salt } = await getUser({
      email: user.email,
    });

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

    const { password_hash, password_salt } = await getUser({
      id: user.id,
    });

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
          encoded: encodeBase32NoPadding(new TextEncoder().encode(code)),
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

app.post(
  "/email/request-change",
  authMiddleware(true),
  zValidator(
    "json",
    requestChangeEmailSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    const { user } = auth();
    const { email } = c.req.valid("json");

    const pastAttempts = await getVerificationCodeAttemptWithin(
      user.id,
      VerificationEnum.REQUEST_CHANGE_EMAIL,
      REQUEST_CHANGE_EMAIL_ALLOWED_ATTEMPT_DURATION,
    );

    if (pastAttempts >= REQUEST_CHANGE_EMAIL_ATTEMPT) {
      return errorResponse(
        c,
        "Too many requests",
        StatusCodes.TOO_MANY_REQUESTS,
      );
    }

    await invalidateVerificationCodes(
      user.id,
      VerificationEnum.REQUEST_CHANGE_EMAIL,
    );

    const { otp } = await createVerificationCode(
      {
        type: VerificationEnum.REQUEST_CHANGE_EMAIL,
        user_id: user.id,
        expires_in: REQUEST_CHANGE_EMAIL_ALLOWED_ATTEMPT_DURATION,
      },
      {
        email,
      },
    );

    try {
      await sendMail({
        to: [{ name: user.name, email: user.email }],
        ...requestChangeEmailTemplate(otp),
      });
    } catch (e) {
      console.log("[REQUEST EMAIL CHANGE MAIL ERROR]", e);
    }

    return successResponse(
      c,
      undefined,
      StatusCodes.OK,
      "You will received a email containing your otp",
    );
  },
);

app.post(
  "/email/confirm-change",
  authMiddleware(true),
  zValidator(
    "json",
    confirmChangeEmailSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    const { code } = c.req.valid("json");
    const { user } = auth();

    const requestChangeEmailCode = await getVerificationCode(
      code,
      VerificationEnum.REQUEST_CHANGE_EMAIL,
      user.id,
    );

    try {
      if (
        !requestChangeEmailCode ||
        isPast(requestChangeEmailCode.expired_at)
      ) {
        return errorResponse(
          c,
          "invalid or expired otp",
          StatusCodes.FORBIDDEN,
        );
      }

      const email = (requestChangeEmailCode.metadata as { email?: string })
        .email;

      if (!email) {
        return errorResponse(
          c,
          "invalid or expired otp",
          StatusCodes.FORBIDDEN,
        );
      }

      await updateUserEmail(user.id, email);

      return successResponse(c, undefined, StatusCodes.OK, "email updated");
    } finally {
      if (requestChangeEmailCode) {
        await removeVerificationCode(requestChangeEmailCode.id, user.id);
      }
    }
  },
);

export default app;
