import { serve } from "@hono/node-server";
import { errorResponse, successResponse } from "commons/utils/api_response.js";
import { getEnv } from "config/env/index.js";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import StatusCodes from "http-status";
import authRoute from "@/modules/auth/auth.routes.js";

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

app.basePath("/api/v1").route("/auth", authRoute);

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
