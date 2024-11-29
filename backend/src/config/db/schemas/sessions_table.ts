import {
  integer,
  pgTable,
  text,
  timestamp,
  varchar,
  boolean,
} from "drizzle-orm/pg-core";
import { ulid } from "ulid";
import { dateTimestampFields } from "./shared";
import { userTable } from "./users_table";
import { relations, type InferSelectModel } from "drizzle-orm";

export const sessionTable = pgTable("sessions", {
  id: varchar("id", { length: 50 })
    .primaryKey()
    .$defaultFn(() => ulid()),
  user_id: varchar("user_id", { length: 50 })
    .notNull()
    .references(() => userTable.id, { onDelete: "cascade" }),
  two_factor_verified: boolean("two_factor_verified"),
  user_agent: varchar("user_agent", { length: 255 }),
  last_used: timestamp("last_used", { mode: "date" }),
  expires_at: timestamp("expires_at", {
    mode: "date",
  }).notNull(),

  ...dateTimestampFields,
});

export type Session = InferSelectModel<typeof sessionTable>;

export const sessionRelations = relations(sessionTable, ({ one }) => ({
  user: one(userTable, {
    references: [userTable.id],
    fields: [sessionTable.user_id],
  }),
}));
