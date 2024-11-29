import { TimeSpan } from "oslo";
import { HMAC } from "oslo/crypto";
import { createJWT, JWT, validateJWT } from "oslo/jwt";
import { isPast } from "date-fns";
import { JwtPayload } from "../interface/jwt";

export type JwtOption = Partial<Pick<JWT, "audiences" | "issuer">>;
export type JwtToken = { token: string; expiresIn: TimeSpan };
export async function signToken<Payload extends JwtPayload>(
  payload: Payload,
  secret: string | ArrayBuffer,
  expiresIn: TimeSpan,
  option?: JwtOption,
): Promise<JwtToken> {
  secret ??= await new HMAC("SHA-256").generateKey();

  if (typeof secret === "string") {
    secret = await new Blob([secret]).arrayBuffer();
  }

  const jwt = await createJWT("HS256", secret, payload, {
    ...((option as any) ?? {}),
    expiresIn: expiresIn,
    includeIssuedTimestamp: true,
  });

  return { token: jwt, expiresIn };
}

export async function verifyToken<Payload>(token: string, secret: string) {
  const jwt = await validateJWT(
    "HS256",
    await new Blob([secret]).arrayBuffer(),
    token,
  );

  if (jwt.algorithm !== "HS256") {
    throw new InvalidJWTToken("invalid token");
  }

  if (!jwt.expiresAt || isPast(jwt.expiresAt)) {
    throw new ExpiredJWTToken("token has expired");
  }

  return <Payload>jwt.payload;
}

export class InvalidJWTToken extends Error {}
export class ExpiredJWTToken extends Error {}
