import {
  boolean,
  pgTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { ulid } from "ulid";
import { userTable } from "./users_table";
import { dateTimestampFields } from "./shared";
import { InferSelectModel, relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { TypeOf, z } from "zod";
import { getEnv } from "config/env";

export const passwordResetSessionTable = pgTable("password_reset_session", {
  id: varchar("id", { length: 50 })
    .primaryKey()
    .$defaultFn(() => ulid()),

  user_id: varchar("user_id", { length: 50 })
    .references(() => userTable.id, {
      onDelete: "cascade",
    })
    .notNull(),

  expired_at: timestamp("expired_at", { mode: "date" }).notNull(),
  email: varchar("email", { length: 255 }).notNull(),
  code: text("code"),
  email_verified: boolean("email_verified").notNull(),
  two_factor_verified: boolean("email_verified"),
  ...dateTimestampFields,
});

export const passwordResetSessionRelations = relations(
  passwordResetSessionTable,
  ({ one }) => ({
    recoveryUser: one(userTable, {
      references: [userTable.id],
      fields: [passwordResetSessionTable.user_id],
    }),
  }),
);

export const createPasswordResetSessionSchema = createInsertSchema(
  passwordResetSessionTable,
  {
    user_id: z.string().min(1).max(50),
    email: z.string().email(),
    code: z.string().min(getEnv("OTP_LENGTH")).max(512),
    expired_at: z.coerce.date(),
    two_factor_verified: z.boolean().nullish(),
  },
).pick({
  user_id: true,
  email: true,
  email_verified: true,
  code: true,
  two_factor_verified: true,
  expired_at: true,
});

export type CreatePasswordResetSessionPayload = TypeOf<
  typeof createPasswordResetSessionSchema
>;
