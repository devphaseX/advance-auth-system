import { db } from "@/db/init";
import { userPreferenceTable } from "@/db/schemas";
import { eq } from "drizzle-orm";

export const setMfaSecret = async (userId: string, secret: string) => {
  const [updatedPref] = await db
    .update(userPreferenceTable)
    .set({
      enabled_2fa: true,
      two_factor_secret: secret,
    })
    .where(eq(userPreferenceTable.user_id, userId))
    .returning();

  return !!updatedPref;
};
