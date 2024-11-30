import { JwtAccessPayload } from "@/commons/interface/jwt";
import { AuthUser } from "@/modules/auth/auth.service";
import { getContext } from "hono/context-storage";

export type RequestEnv = {
  Variables: {
    session?: JwtAccessPayload;
    user?: AuthUser;
  };
};

export const setAuthSession = (user: AuthUser, session: JwtAccessPayload) => {
  const ctx = getContext<RequestEnv>();
  ctx.set("session", session);
  ctx.set("user", user);
};

type Session = JwtAccessPayload;

type AuthSession =
  | { session: Session; user: AuthUser }
  | { session: null; user: null };

export const getAuthSession = (): AuthSession => {
  const ctx = getContext<RequestEnv>();
  const session = ctx.get("session");
  const user = ctx.get("user");
  if (!(session && user)) {
    return { session: null, user: null };
  }

  return { session, user };
};
