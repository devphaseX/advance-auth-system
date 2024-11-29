import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import {
  loginUserSchema,
  registerUserSchema,
} from "commons/validators/auth.validator.js";
import {
  checkEmailAvailability,
  createUser,
  getUserWithPassword,
} from "./auth.service.js";
import { hash, verify } from "@/commons/utils/hash.js";
import {
  errorResponse,
  successResponse,
} from "@/commons/utils/api_response.js";
import StatusCodes from "http-status";
import { ErrorCode } from "@/commons/enums/error_code.js";
import { createSession } from "@/commons/utils/session.js";
import { ulid } from "ulid";
import { createDate, TimeSpan } from "oslo";
import { getEnv } from "config/env/index.js";
import { createVerificationCode } from "@/services/verification.service.js";
import { VerificationEnum } from "@/commons/enums/verification.enum.js";

const app = new Hono();

app.post("/sign-up", zValidator("json", registerUserSchema), async (c) => {
  const payload = c.req.valid("json");

  if (await checkEmailAvailability(payload.email)) {
    return errorResponse(c, "email not available", StatusCodes.CONFLICT, {
      error_code: ErrorCode.AUTH_EMAIL_ALREADY_EXISTS,
    });
  }

  const { hash: password_hash, salt } = await hash(payload.password);
  const password_salt = salt.toString("base64");

  const newUser = await createUser({
    name: payload.name,
    email: payload.email,
    password_hash,
    password_salt,
  });

  const verifyEmailCode = await createVerificationCode({
    type: VerificationEnum.EMAIL_VERIFY,
    user_id: newUser.id,
    expired_at: createDate(getEnv("OTP_EXPIRES_IN")),
  });

  return successResponse(c, {
    data: { user: newUser },
  });
});

app.post("/sign-in", zValidator("json", loginUserSchema), async (c) => {
  const { email, password, userAgent } = c.req.valid("json");

  if (!(await checkEmailAvailability(email))) {
    return errorResponse(c, "invalid credentials", StatusCodes.NOT_FOUND, {
      error_code: ErrorCode.AUTH_USER_NOT_FOUND,
    });
  }

  const user = await getUserWithPassword(email);
  if (!user.password_hash) {
    return errorResponse(
      c,
      "invalid credentials",
      StatusCodes.PRECONDITION_FAILED,
      {
        error_code: ErrorCode.AUTH_USER_NOT_FOUND,
      },
    );
  }

  const passwordCheckPass = await verify(
    password,
    user.password_hash!,
    Buffer.from(user.password_salt!, "base64"),
  );

  if (!passwordCheckPass) {
    return errorResponse(c, "invalid credentials", StatusCodes.NOT_FOUND, {
      error_code: ErrorCode.AUTH_USER_NOT_FOUND,
    });
  }

  const session = await createSession({
    user_id: user.id,
    user_agent: userAgent!,
  });

  return successResponse(c, {
    data: {
      user: {
        id: user.id,
        email: user.email,
      },
    },
  });
});

export default app;
