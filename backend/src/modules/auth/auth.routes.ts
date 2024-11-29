import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import {
  loginUserSchema,
  refreshTokenSchema,
  registerUserSchema,
} from "commons/validators/auth.validator.js";
import {
  checkEmailAvailability,
  createUser,
  getUser,
  getUserWithPassword,
} from "./auth.service.js";
import { hash, verify } from "@/commons/utils/hash.js";
import {
  errorResponse,
  successResponse,
} from "@/commons/utils/api_response.js";
import StatusCodes from "http-status";
import { ErrorCode } from "@/commons/enums/error_code.js";
import {
  createSession,
  invalidateSession,
  validateSessionToken,
} from "@/commons/utils/session.js";
import { ulid } from "ulid";
import { createDate, TimeSpan } from "oslo";
import { getEnv } from "config/env/index.js";
import { createVerificationCode } from "@/services/verification.service.js";
import { VerificationEnum } from "@/commons/enums/verification.enum.js";
import { signToken, verifyToken } from "@/commons/utils/token.js";
import {
  JwtAccessPayload,
  JwtRefreshPayload,
} from "@/commons/interface/jwt.js";
import {
  getRefreshTokenCookie,
  setAuthenicationCookie,
} from "@/commons/utils/cookie.js";
import { validateErrorHook } from "@/commons/utils/app_error.js";
import tryit from "@/commons/utils/tryit.js";
import { getSession } from "../session/session.service.js";
import { isPast } from "date-fns";
import { getCookie } from "hono/cookie";

const app = new Hono();

app.post(
  "/sign-up",
  zValidator(
    "json",
    registerUserSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
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
  },
);

app.post(
  "/sign-in",
  zValidator(
    "json",
    loginUserSchema,
    validateErrorHook("invalid request body"),
  ),
  async (c) => {
    let userAgent = c.req.valid("json").userAgent ?? c.req.header("User-Agent");
    const { email, password } = c.req.valid("json");

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

    const accessToken = await signToken<JwtAccessPayload>(
      {
        user_id: user.id,
        session_id: session.id,
        enable_2fa: user.preference.enabled_2fa,
        two_factor_verified: !user.preference.enabled_2fa,
      },
      getEnv("AUTH_SECRET"),
      getEnv("AUTH_EXPIRES_IN"),
      { audiences: ["user"] },
    );

    const refreshToken = await signToken<JwtRefreshPayload>(
      { session_id: session.id },
      getEnv("AUTH_REFRESH_SECRET"),
      getEnv("AUTH_REFRESH_EXPIRES_IN"),
      { audiences: ["user"] },
    );

    setAuthenicationCookie(c, { access: accessToken, refresh: refreshToken });
    return successResponse(c, {
      data: {
        user: await getUser({ id: user.id }),
        mfaRequired: Boolean(user.preference.enabled_2fa),
        accessToken: {
          value: accessToken.token,
          expiredAt: createDate(accessToken.expiresIn),
        },
        refreshToken: {
          value: refreshToken.token,
          expiredAt: createDate(refreshToken.expiresIn),
        },
      },
    });
  },
);

app.post("/refresh", zValidator("json", refreshTokenSchema), async (c) => {
  let { refreshToken } = c.req.valid("json");
  refreshToken ??= getRefreshTokenCookie(c);

  if (!refreshToken) {
    return errorResponse(c, "missing refresh token", StatusCodes.BAD_REQUEST);
  }

  const [token, err] = await tryit(
    verifyToken<JwtRefreshPayload>(refreshToken, getEnv("AUTH_REFRESH_SECRET")),
  );

  if (err) {
    return errorResponse(c, err.message, StatusCodes.UNAUTHORIZED);
  }

  const sessionResult = await validateSessionToken(token.session_id);

  if (!(sessionResult.session && sessionResult.user)) {
    return errorResponse(
      c,
      "invalid or expired token",
      StatusCodes.UNAUTHORIZED,
    );
  }

  const {
    user: { id: userId },
    refreshed,
    session,
  } = sessionResult;
  const user = await getUser({ id: userId });
  const accessToken = await signToken<JwtAccessPayload>(
    {
      user_id: user.id,
      session_id: session.id,
      enable_2fa: user.preference.enabled_2fa,
      two_factor_verified: !user.preference.enabled_2fa,
    },
    getEnv("AUTH_SECRET"),
    getEnv("AUTH_EXPIRES_IN"),
    { audiences: ["user"] },
  );

  if (refreshed) {
    const refreshToken = await signToken<JwtRefreshPayload>(
      { session_id: session.id },
      getEnv("AUTH_REFRESH_SECRET"),
      getEnv("AUTH_REFRESH_EXPIRES_IN"),
      { audiences: ["user"] },
    );

    setAuthenicationCookie(c, { access: accessToken, refresh: refreshToken });
    return successResponse(c, {
      data: {
        accessToken: {
          value: accessToken.token,
          expiredAt: createDate(accessToken.expiresIn),
        },
        refreshToken: {
          value: refreshToken.token,
          expiredAt: createDate(refreshToken.expiresIn),
        },
      },
    });
  }

  return successResponse(c, {
    data: {
      accessToken: {
        value: accessToken.token,
        expiredAt: createDate(accessToken.expiresIn),
      },
    },
  });
});

export default app;
