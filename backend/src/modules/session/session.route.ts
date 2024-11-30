import { auth, authMiddleware } from "@/middlewares/auth";
import { Hono } from "hono";
import { deleteSession, getSession, getSessions } from "./session.service";
import { errorResponse, successResponse } from "@/commons/utils/api_response";
import StatusCodes from "http-status";

const app = new Hono();

app.get("/all", authMiddleware, async (c) => {
  const { session } = auth();

  const sessions = await getSessions(session.user_id, session.session_id);
  return successResponse(c, { data: { sessions } });
});

app.get("/:id", authMiddleware, async (c) => {
  const { id } = c.req.param();
  const { session: currentSession } = auth();

  const session = await getSession(id);

  if (session?.user_id !== currentSession.user_id) {
    return errorResponse(c, "session not found");
  }
  return successResponse(c, { data: { session } });
});

app.delete("/:id", authMiddleware, async (c) => {
  const { id } = c.req.param();
  const { session: currentSession } = auth();

  const session = await getSession(id);

  if (session?.user_id !== currentSession.user_id) {
    return errorResponse(c, "session not found");
  }

  if (session.id === currentSession.session_id) {
    return errorResponse(
      c,
      "you are not allowed to delete the current session. Use the logout feature",
      StatusCodes.FORBIDDEN,
    );
  }

  await deleteSession(id, currentSession.user_id);
  return successResponse(c, undefined, StatusCodes.OK, "session deleted");
});

export default app;
