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
import { relations } from "drizzle-orm";

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
