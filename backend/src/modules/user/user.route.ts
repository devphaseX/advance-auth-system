import { RequestEnv } from "@/middlewares/context_storage";
import { Hono } from "hono";
import { auth, authMiddleware } from "@/middlewares/auth";
import { successResponse } from "@/commons/utils/api_response";

const app = new Hono<RequestEnv>();

app.get("/current", authMiddleware(true), async (c) => {
  const session = auth();
  return successResponse(c, { data: { user: session.user } });
});

export default app;
