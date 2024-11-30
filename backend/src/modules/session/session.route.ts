import { auth, authMiddleware } from "@/middlewares/auth";
import { Hono } from "hono";
import { getSessions } from "./session.service";
import { successResponse } from "@/commons/utils/api_response";

const app = new Hono();

app.get("/all", authMiddleware, async (c) => {
  const { session } = auth();

  const sessions = await getSessions(session.user_id, session.session_id);
  return successResponse(c, { data: { sessions } });
});

export default app;
