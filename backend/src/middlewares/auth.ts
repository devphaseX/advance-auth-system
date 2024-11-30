import { JwtAccessPayload } from "@/commons/interface/jwt";
import { errorResponse } from "@/commons/utils/api_response";
import { getAccessTokenCookie } from "@/commons/utils/cookie";
import { verifyToken } from "@/commons/utils/token";
import tryit from "@/commons/utils/tryit";
import { getEnv } from "config/env";
import { createMiddleware } from "hono/factory";
import StatusCodes from "http-status";
import { getAuthSession, setAuthSession } from "./context_storage";
import { HTTPException } from "hono/http-exception";
import { updateSessionLastUsed } from "@/modules/session/session.service";

export const authMiddleware = createMiddleware(async (c, next) => {
  let token = getAccessTokenCookie(c)?.trim();
  let retrievedTokenFromHeader = false;

  if (!token) {
    token = c.req.header("Authorization")?.trim();
    retrievedTokenFromHeader = true;
  }

  if (!token) {
    return errorResponse(
      c,
      "Missing authentication token",
      StatusCodes.UNAUTHORIZED,
    );
  }

  if (retrievedTokenFromHeader && token.startsWith("Bearer")) {
    return errorResponse(
      c,
      "Invalid authentication type. Use 'Bearer' token",
      StatusCodes.UNAUTHORIZED,
    );
  }

  if (retrievedTokenFromHeader) {
    [, token] = token.split(/\b\s+\b/);
  }

  if (!token) {
    return errorResponse(c, "Invalid Bearer token", StatusCodes.UNAUTHORIZED);
  }

  const [payload, err] = await tryit(
    verifyToken<JwtAccessPayload>(token, getEnv("AUTH_SECRET")),
  );

  if (err) {
    return errorResponse(c, err.message, StatusCodes.UNAUTHORIZED);
  }

  setAuthSession(payload);
  await next();
  await updateSessionLastUsed(payload.session_id);
});

export const auth = () => {
  const session = getAuthSession();

  if (!session) {
    throw new HTTPException(StatusCodes.UNAUTHORIZED, {
      message: "unauthorized",
    });
  }

  return session;
};
