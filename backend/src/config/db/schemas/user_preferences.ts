import { boolean, jsonb, pgTable, text, varchar } from "drizzle-orm/pg-core";
import { ulid } from "ulid";
import { z } from "zod";
import { dateTimestampFields } from "./shared";
import { relations, type InferSelectModel } from "drizzle-orm";
import { userTable } from "./users_table";

export const userPreferenceTable = pgTable("user_preferences", {
  id: varchar("id")
    .primaryKey()
    .$defaultFn(() => ulid()),

  enabled_2fa: boolean("enabled_2fa").default(false).notNull(),
  enabled_email_notification: boolean("enabled_email_notification")
    .default(true)
    .notNull(),
  two_factor_secret: text("two_factor_secret"),
  user_id: varchar("user_id").references(() => userTable.id, {
    onDelete: "cascade",
  }),
  recovery_codes: jsonb("recovery_codes").$type<string[]>(),
  ...dateTimestampFields,
});

export type UserPreference = InferSelectModel<typeof userPreferenceTable>;

export const userPreferenceRelations = relations(
  userPreferenceTable,
  ({ one }) => ({
    user: one(userTable, {
      references: [userTable.id],
      fields: [userPreferenceTable.user_id],
    }),
  }),
);
