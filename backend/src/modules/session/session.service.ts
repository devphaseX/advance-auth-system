import { db } from "@/db/init";
import { Session, sessionTable } from "@/db/schemas";
import { and, desc, eq, sql } from "drizzle-orm";
import {
  PgColumn,
  PgTableWithColumns,
  SelectedFields,
  pgTable,
} from "drizzle-orm/pg-core";

export const getSession = async (sessionId: string) => {
  const [session] = await db
    .select()
    .from(sessionTable)
    .where(eq(sessionTable.id, sessionId));

  return session;
};

export const updateSessionLastUsed = async (sessionId: string) => {
  const [updatedLastUsedSession] = await db
    .update(sessionTable)
    .set({ last_used: new Date() })
    .where(eq(sessionTable.id, sessionId))
    .returning();

  return !!updatedLastUsedSession;
};

export const getSessions = (userId: string, activeSessionId?: string) => {
  return db
    .select({
      id: sessionTable.id,
      two_factor_verified: sessionTable.two_factor_verified,
      expires_at: sessionTable.expires_at,
      user_agent: sessionTable.user_agent,
      last_used: sessionTable.last_used,
      user_id: sessionTable.user_id,
      is_current: sql<boolean>`${sessionTable.id} = ${activeSessionId ?? ""}`,
      created_at: sessionTable.created_at,
      updated_at: sessionTable.updated_at,
    } satisfies Record<keyof Session, any> & Record<string, any>)
    .from(sessionTable)
    .where(eq(sessionTable.user_id, userId))
    .orderBy(desc(sessionTable.created_at));
};

export const deleteSession = async (sessionId: string, userId: string) => {
  const [deletedSession] = await db
    .delete(sessionTable)
    .where(
      and(eq(sessionTable.id, sessionId), eq(sessionTable.user_id, userId)),
    )
    .returning();

  return !!deletedSession;
};
