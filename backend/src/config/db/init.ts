import "dotenv/config";
import { pgTable, serial, text, varchar } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "@/db/schemas/index.js";

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

export const db = drizzle({ client: pool, schema });
