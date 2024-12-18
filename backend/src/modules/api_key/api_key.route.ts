import { errorResponse, successResponse } from "@/commons/utils/api_response";
import { createApiKeySchema } from "@/db/schemas";
import { auth, authMiddleware } from "@/middlewares/auth";
import {
  createApiKey,
  deactivateApiKey,
  generateApiKey,
  getApiKeyById,
  getApiKeys,
  rotateApiKey,
} from "@/services/api_key.service";
import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { TimeSpan } from "oslo";
import StatusCodes from "http-status";
import {
  deactivateApiKeySchema,
  rotateApiKeySchema,
} from "@/commons/validators/api_key.validator";
import { isAfter, isPast } from "date-fns";

const app = new Hono();
app.post(
  "/",
  authMiddleware(true),
  zValidator("json", createApiKeySchema),
  async (c) => {
    const payload = c.req.valid("json");
    if (
      !(
        payload.expires_in == null ||
        payload.expires_in === -1 ||
        payload.expires_in >= new TimeSpan(5, "m").seconds()
      )
    ) {
      return errorResponse(
        c,
        "an expire bound api should set a minimum time of 5 minutes",
        StatusCodes.UNPROCESSABLE_ENTITY,
      );
    }

    const { apiKey, key } = await createApiKey({
      name: payload.name,
      expires_in: payload.expires_in,
      scopes: payload.scopes,
    });

    return successResponse(c, { data: { apiKey, key } });
  },
);

app.get("/", authMiddleware(true), async (c) => {
  const apiContents = await getApiKeys(c);
  return successResponse(c, apiContents);
});

app.get("/:id", authMiddleware(true), async (c) => {
  const apiKey = await getApiKeyById(c.req.param("id"));

  if (!apiKey) {
    return errorResponse(c, "api key not found", StatusCodes.NOT_FOUND);
  }
  return successResponse(c, { apiKey });
});

app.post(
  "/:id/deactivate",
  authMiddleware(true),
  zValidator("json", deactivateApiKeySchema),
  async (c) => {
    const claim = auth();
    const payload = c.req.valid("json");

    let apiKey = await getApiKeyById(c.req.param("id"));
    if (!apiKey) {
      return errorResponse(c, "api key not found", StatusCodes.NOT_FOUND);
    }

    if (!apiKey.is_active) {
      return errorResponse(
        c,
        "api key already inactive",
        StatusCodes.FORBIDDEN,
      );
    }

    if (apiKey.rotation_window_ends && isPast(apiKey.rotation_window_ends)) {
      return errorResponse(
        c,
        "api key in rotation process, deletion not allowed",
        StatusCodes.FORBIDDEN,
      );
    }

    apiKey = await deactivateApiKey(apiKey.id, {
      deletedBy: claim.user.id,
      gracePeriod: payload.gracePeriod,
      immediately: payload.immediately,
      deletedReason: payload.deletedReason,
    });

    return successResponse(
      c,
      undefined,
      StatusCodes.OK,
      payload.immediately
        ? "api key deactivated successfully"
        : `api key scheduled for deactivation at ${apiKey.deleted_at?.toISOString()}`,
    );
  },
);

app.post(
  "/:id/rotate",
  authMiddleware(true),
  zValidator("json", rotateApiKeySchema),
  async (c) => {
    const payload = c.req.valid("json");
    let apiKey = await getApiKeyById(c.req.param("id"));

    if (!apiKey) {
      return errorResponse(c, "api key not found", StatusCodes.NOT_FOUND);
    }

    if (!apiKey.is_active) {
      return errorResponse(
        c,
        "api key already inactive",
        StatusCodes.FORBIDDEN,
      );
    }

    if (apiKey.rotation_window_ends) {
      return errorResponse(
        c,
        "api key in rotation process",
        StatusCodes.FORBIDDEN,
      );
    }

    const { apiKey: newApiKey, key: newKey } = await rotateApiKey(
      apiKey,
      payload,
    );

    return successResponse(
      c,
      {
        data: {
          apiKey: newApiKey,
          key: newKey,
        },
      },
      StatusCodes.CREATED,
      `Store this new API key securely. It will not be shown again.
    The old API key will remain active for ${apiKey.expired_at?.toISOString()}`,
    );
  },
);

export default app;
