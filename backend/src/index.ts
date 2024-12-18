import { serve } from "@hono/node-server";
import { errorResponse } from "commons/utils/api_response.js";
import { getEnv } from "config/env/index.js";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import authRoute from "@/modules/auth/auth.routes.js";
import userRoute from "@/modules/user/user.route";
import sessionRoute from "@/modules/session/session.route";
import apiKeyRoute from "@/modules/api_key/api_key.route";

import mfaRoute from "@/modules/mfa/mfa.routes";
import { contextStorage } from "hono/context-storage";
const app = new Hono();

app.use(
  cors({
    origin: getEnv("APP_ORIGIN"),
    // allowHeaders: ["X-Custom-Header", "Upgrade-Insecure-Requests"],
    allowMethods: ["POST", "GET", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
    credentials: true,
  }),
);

app
  .basePath("/api/v1")
  .use(contextStorage())
  .route("/auth", authRoute)
  .route("/users", userRoute)
  .route("/sessions", sessionRoute)
  .route("/mfa", mfaRoute)
  .route("/api-keys", apiKeyRoute);

app.onError(async (err, c) => {
  if (err instanceof HTTPException) {
    return errorResponse(c, err.message, err.status);
  }
  return errorResponse(c, err?.message ?? "Unknown error occurred");
});

const port = getEnv("PORT");
console.log(`Server is running on http://localhost:${port}`);

serve({
  fetch: app.fetch,
  port,
});
