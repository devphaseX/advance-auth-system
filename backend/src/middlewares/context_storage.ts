import { JwtAccessPayload } from "@/commons/interface/jwt";
import { AuthUser } from "@/modules/auth/auth.service";
import { getContext } from "hono/context-storage";

export type RequestEnv = {
  Variables: {
    session?: JwtAccessPayload;
  };
};

export const setAuthSession = (session: JwtAccessPayload) => {
  getContext<RequestEnv>().set("session", session);
};

export const getAuthSession = () => {
  return getContext<RequestEnv>().get("session");
};
