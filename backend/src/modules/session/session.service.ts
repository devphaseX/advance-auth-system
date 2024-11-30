import { db } from "@/db/init";
import { sessionTable } from "@/db/schemas";
import { eq } from "drizzle-orm";

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
