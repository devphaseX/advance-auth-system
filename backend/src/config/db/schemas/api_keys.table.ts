import { ApiScopeKey } from "@/services/api_key.service";
import { InferSelectModel } from "drizzle-orm";
import {
  boolean,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { ulid } from "ulid";
import { TypeOf, z } from "zod";
import { userTable } from "./users_table";
import { dateTimestampFields } from "./shared";

export const apiKeyTable = pgTable("api_keys", {
  id: varchar("id", { length: 50 })
    .primaryKey()
    .$defaultFn(() => ulid()),
  name: varchar("name", { length: 50 }).notNull(),
  prefix: varchar("prefix", { length: 255 }).notNull(),
  hash: text("hash").notNull(),
  is_active: boolean("is_active").default(true).notNull(),
  scopes: jsonb("scopes").$type<Array<ApiScopeKey>>(),
  user_id: varchar("user_id").references(() => userTable.id, {
    onDelete: "cascade",
  }),
  last_used_at: timestamp("last_used_at", {
    mode: "date",
    withTimezone: true,
  }),
  expires_in: integer("expires_in"),
  expired_at: timestamp("expired_at", { mode: "date", withTimezone: true }),
  replaced_by_key_id: varchar("replaced_by_key_id", { length: 50 }),
  replaces_key_id: varchar("replaced_by_key_id", { length: 50 }),
  rotation_window_ends: timestamp("rotation_window_ends", {
    mode: "date",
    withTimezone: true,
  }),
  deleted_at: timestamp("deleted_at", {
    mode: "date",
    withTimezone: true,
  }),
  deleted_reason: varchar("deleted_reason", { length: 255 }),
  deleted_by: varchar("deleted_by", { length: 50 }),
  ...dateTimestampFields,
});

export type ApiKey = InferSelectModel<typeof apiKeyTable>;

export const createApiKeySchema = createInsertSchema(apiKeyTable, {
  name: z.string().min(1).max(255),
  prefix: z.string().min(1).max(20),
  hash: z.string(),
  scopes: z.string().array(),
  expires_in: z.coerce.number(),
}).pick({
  name: true,
  scopes: true,
  expires_in: true,
});

export type CreateApiKeyPayload = TypeOf<typeof createApiKeySchema> & {
  replaces_key_id?: string;
};
