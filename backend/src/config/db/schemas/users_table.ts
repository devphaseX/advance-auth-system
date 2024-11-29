import { pgTable, text, varchar, timestamp } from "drizzle-orm/pg-core";
import { relations, type InferInsertModel } from "drizzle-orm";
import { ulid } from "ulid";
import { dateTimestampFields } from "./shared";
import { sessionTable } from "./sessions_table";
import { userPreferenceTable } from "./user_preferences";
import { verificationCodeTable } from "./verification_codes_table";

export const userTable = pgTable("users", {
  id: varchar("id", { length: 50 })
    .primaryKey()
    .$defaultFn(() => ulid()),
  name: varchar("name", { length: 255 }).notNull(),
  email: varchar("email", { length: 255 }).notNull(),
  email_verified_at: timestamp("email_verified_at"),
  password_hash: text("password_hash"),
  password_salt: text("password_salt"),
  ...dateTimestampFields,
});

export type User = InferInsertModel<typeof userTable>;

export const userRelations = relations(userTable, ({ many, one }) => ({
  sessions: many(sessionTable),
  preference: one(userPreferenceTable, {
    references: [userPreferenceTable.user_id],
    fields: [userTable.id],
  }),
  verification_codes: many(verificationCodeTable),
}));
