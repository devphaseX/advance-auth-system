import { CreatePasswordResetSessionPayload } from "@/commons/validators/password_reset_session";
import { db } from "@/db/init";
import { passwordResetSessionTable } from "@/db/schemas";
import { and, eq } from "drizzle-orm";

export async function createPasswordResetSession(
  payload: CreatePasswordResetSessionPayload,
) {
  const [passwordSession] = await db
    .insert(passwordResetSessionTable)
    .values(payload)
    .returning();

  return passwordSession;
}

export async function getPasswordResetSession(id: string) {
  const [session] = await db
    .select()
    .from(passwordResetSessionTable)
    .where(eq(passwordResetSessionTable.id, id));

  return session;
}

export async function markPasswordSessionEmailAsVerified(
  id: string,
  userId: string,
) {
  const [verifiedEmailSession] = await db
    .update(passwordResetSessionTable)
    .set({ email_verified: true })
    .where(
      and(
        eq(passwordResetSessionTable.user_id, userId),
        eq(passwordResetSessionTable.id, id),
      ),
    )
    .returning();

  return verifiedEmailSession;
}

export async function markPasswordSession2faAsVerified(
  id: string,
  userId: string,
) {
  const [verifiedEmailSession] = await db
    .update(passwordResetSessionTable)
    .set({ two_factor_verified: true })
    .where(
      and(
        eq(passwordResetSessionTable.user_id, userId),
        eq(passwordResetSessionTable.id, id),
      ),
    )
    .returning();

  return verifiedEmailSession;
}
