import { errorResponse } from "@/commons/utils/api_response";
import {
  ApiScopeKey,
  getApiKeyByHash,
  hashApiKey,
  updateApiKeyLastUsed,
  validateApiKey,
} from "@/services/api_key.service";
import { getEnv } from "config/env";
import { isPast } from "date-fns";
import { createMiddleware } from "hono/factory";
import StatusCodes from "http-status";
import { getApiKeyAuth, setApiKeyAuth } from "./context_storage";
import { HTTPException } from "hono/http-exception";

export const withApiKeyAuth = (...scopes: ApiScopeKey[]) => {
  if (!scopes.length) {
    throw new Error("no api scope provided");
  }

  return createMiddleware(async (c, next) => {
    const apiToken = c.req.header(getEnv("API_KEY_HEADER_NAME"));
    if (!apiToken) {
      return errorResponse(
        c,
        "api key missing in header",
        StatusCodes.UNAUTHORIZED,
      );
    }

    if (!validateApiKey(apiToken)) {
      return errorResponse(c, "invalid api key", StatusCodes.UNAUTHORIZED);
    }

    const apiKey = await getApiKeyByHash(hashApiKey(apiToken));

    if (
      !apiKey ||
      (apiKey.deleted_at && !apiKey.is_active) ||
      (apiKey.rotation_window_ends && isPast(apiKey.rotation_window_ends))
    ) {
      return errorResponse(c, "invalid api key", StatusCodes.UNAUTHORIZED);
    }

    const apiKeyScopes = new Set(apiKey.scopes ?? []);
    for (const scope of scopes) {
      if (!apiKeyScopes.has(scope)) {
        return errorResponse(
          c,
          "you are not permitted to access this resource",
          StatusCodes.FORBIDDEN,
        );
      }
    }

    setApiKeyAuth(apiKey);
    await next();
    await updateApiKeyLastUsed(apiKey.id).catch((e) => {
      console.error(
        new Error(
          `Failed to update API key last use: ${e.message ?? String(e)}`,
        ),
      );
    });
  });
};

export const apiAuth = () => {
  const apiKey = getApiKeyAuth();
  if (!apiKey) {
    throw new HTTPException(StatusCodes.UNAUTHORIZED, {
      message: "unauthorized",
    });
  }
  return apiKey;
};
