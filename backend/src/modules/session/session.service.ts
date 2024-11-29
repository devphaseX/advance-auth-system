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
