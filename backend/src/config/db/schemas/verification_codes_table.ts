import { VerificationEnum } from "@/commons/enums/verification.enum.js";
import { jsonb, pgTable, text, timestamp, varchar } from "drizzle-orm/pg-core";
import { ulid } from "ulid";
import { dateTimestampFields } from "./shared";
import { relations, type InferSelectModel } from "drizzle-orm";
import { userTable } from "@/db/schemas/users_table";

export const verificationCodeTable = pgTable("verifications_codes", {
  id: varchar("id", { length: 50 })
    .primaryKey()
    .$defaultFn(() => ulid()),

  code: text("code").notNull(),
  user_id: varchar("user_id", { length: 50 })
    .references(() => userTable.id, {
      onDelete: "cascade",
    })
    .notNull(),
  expired_at: timestamp("expired_at", { mode: "date" }).notNull(),
  type: varchar("type").$type<VerificationEnum>().notNull(),
  ...dateTimestampFields,
});
export type VerificationCode = InferSelectModel<typeof verificationCodeTable>;

export const verificationCodeRelations = relations(
  verificationCodeTable,
  ({ one }) => ({
    user: one(userTable, {
      references: [userTable.id],
      fields: [verificationCodeTable.user_id],
    }),
  }),
);
