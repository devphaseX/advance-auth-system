import { eq } from "drizzle-orm";
import { task } from "@trigger.dev/sdk/v3";
import { drizzle } from "drizzle-orm/node-postgres";
import { apiKeyTable } from "@/db/schemas";

const db = drizzle(process.env.DATABASE_URL);

export const scheduleApiKeyDeletion = task({
  id: "schedule_api_key_delete",
  run: async (payload: { keyId: string }) => {
    const [apiKey] = await db
      .select()
      .from(apiKeyTable)
      .where(eq(apiKeyTable.id, payload.keyId));
    if (!(apiKey && apiKey.deleted_at && apiKey.is_active)) {
      return;
    }

    const [deactivatedKey] = await db
      .update(apiKeyTable)
      .set({ is_active: false })
      .where(eq(apiKeyTable.id, payload.keyId))
      .returning();

    return {
      deactivatedKey,
      message: "api deactivated successfully",
    };
  },
});
