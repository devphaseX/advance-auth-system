import { passwordResetSessionTable } from "@/db/schemas";
import { getEnv } from "config/env";
import { createInsertSchema } from "drizzle-zod";
import { TypeOf, z } from "zod";

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
