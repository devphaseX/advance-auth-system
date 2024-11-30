import { JwtAccessPayload } from "@/commons/interface/jwt";
import { errorResponse } from "@/commons/utils/api_response";
import { getAccessTokenCookie } from "@/commons/utils/cookie";
import { verifyToken } from "@/commons/utils/token";
import tryit from "@/commons/utils/tryit";
import { getEnv } from "config/env";
import { createMiddleware } from "hono/factory";
import StatusCodes from "http-status";
import { getAuthSession, RequestEnv, setAuthSession } from "./context_storage";
import { HTTPException } from "hono/http-exception";
import { updateSessionLastUsed } from "@/modules/session/session.service";
import { getUser } from "@/modules/auth/auth.service";

export const authMiddleware = createMiddleware<RequestEnv>(async (c, next) => {
  let token = getAccessTokenCookie(c)?.trim();
  let isHeaderToken = false;

  if (!token) {
    token = c.req.header("Authorization")?.trim();
    isHeaderToken = true;
  }

  if (!token) {
    return errorResponse(
      c,
      "Missing authentication token",
      StatusCodes.UNAUTHORIZED,
    );
  }

  if (isHeaderToken && token.startsWith("Bearer")) {
    return errorResponse(
      c,
      "Invalid authentication type. Use 'Bearer' token",
      StatusCodes.UNAUTHORIZED,
    );
  }

  if (isHeaderToken) {
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

  const authUser = await getUser({ id: payload.user_id });

  if (!authUser) {
    return errorResponse(c, "unauthorized", StatusCodes.UNAUTHORIZED);
  }

  setAuthSession(authUser, payload);
  await next();
  await updateSessionLastUsed(payload.session_id);
});

export const auth = () => {
  const session = getAuthSession();

  if (!session?.session) {
    throw new HTTPException(StatusCodes.UNAUTHORIZED, {
      message: "unauthorized",
    });
  }

  return session;
};
