import { z } from "zod";

export const verifyMfaSetupSchema = z.object({
  secret: z.string().base64(),
  code: z.string().min(5),
});

export const verifyLoginMfaSchema = z.object({
  code: z.string().min(5),
});
