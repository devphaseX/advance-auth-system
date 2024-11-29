import { sessionTable, type Session } from "@/db/schemas/sessions_table.js";
import { userTable, type User } from "@/db/schemas/users_table.js";
import crypto from "crypto";
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase,
} from "@oslojs/encoding";
import { db } from "@/db/init.js";
import { createDate } from "oslo";
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
  sessionId: string,
): Promise<SessionValidationResult> {
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
  let refreshed = false;
  if (
    Date.now() >=
    session.expires_at.getTime() -
      Math.trunc(getEnv("AUTH_REFRESH_EXPIRES_IN").milliseconds() / 2) //session past half expiration time
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
    refreshed = true;
  }
  return { session, refreshed, user };
}

export async function invalidateSession(sessionId: string): Promise<void> {
  await db.delete(sessionTable).where(eq(sessionTable.id, sessionId));
}

export type SessionValidationResult =
  | { session: Session; refreshed?: boolean; user: User }
  | { session: null; user: null };
