import { sessionTable, type Session } from "@/db/schemas/sessions_table.js";
import { userTable, type User } from "@/db/schemas/users_table.js";
import crypto from "crypto";
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase,
} from "@oslojs/encoding";
import { db } from "@/db/init.js";
import { createDate, TimeSpan } from "oslo";
import { sha256 } from "@oslojs/crypto/sha2";
import { eq } from "drizzle-orm";
import { getEnv } from "config/env";

export function generateSessionToken(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const token = encodeBase32LowerCaseNoPadding(bytes);
  return token;
}

type CreateSessionData = Pick<Session, "user_id" | "user_agent">;

export async function createSession(data: CreateSessionData): Promise<Session> {
  const { user_agent, user_id } = data;
  const [newSession] = await db
    .insert(sessionTable)
    .values({
      expires_at: createDate(getEnv("AUTH_REFRESH_EXPIRES_IN")),
      user_id,
      user_agent,
    })
    .returning();

  return newSession;
}

export async function validateSessionToken(
  token: string,
): Promise<SessionValidationResult> {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

  const result = await db
    .select({ user: userTable, session: sessionTable })
    .from(sessionTable)
    .innerJoin(userTable, eq(sessionTable.user_id, userTable.id))
    .where(eq(sessionTable.id, sessionId));

  if (result.length < 1) {
    return { session: null, user: null };
  }

  const { user, session } = result[0];
  if (Date.now() >= Number(session.expires_at)) {
    await db.delete(sessionTable).where(eq(sessionTable.id, session.id));
    return { session: null, user: null };
  }
  if (
    Date.now() >=
    session.expires_at.getTime() -
      getEnv("AUTH_REFRESH_EXPIRES_IN").milliseconds()
  ) {
    session.expires_at = new Date(
      Date.now() + getEnv("AUTH_REFRESH_EXPIRES_IN").milliseconds(),
    );
    await db
      .update(sessionTable)
      .set({
        expires_at: session.expires_at,
      })
      .where(eq(sessionTable.id, session.id));
  }
  return { session, user };
}

export async function invalidateSession(sessionId: string): Promise<void> {
  await db.delete(sessionTable).where(eq(sessionTable.id, sessionId));
}

export type SessionValidationResult =
  | { session: Session; user: User }
  | { session: null; user: null };
