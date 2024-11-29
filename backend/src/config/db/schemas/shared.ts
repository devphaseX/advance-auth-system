import { timestamp } from "drizzle-orm/pg-core";

export const dateTimestampFields = {
  created_at: timestamp("created_at").defaultNow(),
  updated_at: timestamp("updated_at")
    .defaultNow()
    .$onUpdateFn(() => new Date()),
};
