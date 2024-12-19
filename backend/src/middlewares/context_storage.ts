import { JwtAccessPayload } from "@/commons/interface/jwt";
import { ApiKey } from "@/db/schemas";
import { AuthUser } from "@/modules/auth/auth.service";
import { getContext } from "hono/context-storage";

export type RequestEnv = {
  Variables: {
    session?: JwtAccessPayload;
    user?: AuthUser;
    apiKey?: ApiKey;
  };
};

export const setAuthSession = (user: AuthUser, session: JwtAccessPayload) => {
  const ctx = getContext<RequestEnv>();
  ctx.set("session", session);
  ctx.set("user", user);
};

export const setApiKeyAuth = (apiKey: ApiKey) => {
  const ctx = getContext<RequestEnv>();
  ctx.set("apiKey", apiKey);
};

export const getApiKeyAuth = () => {
  const ctx = getContext<RequestEnv>();
  const apiKey = ctx.get("apiKey");
  if (!ctx.get("apiKey")) {
    return null;
  }
  return apiKey;
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
