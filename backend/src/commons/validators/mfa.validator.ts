import { z } from "zod";

export const verifyMfaSetupSchema = z.object({
  secret: z.string().base64(),
  code: z.string().min(5),
});

export const verifyLoginMfaSchema = z.object({
  code: z.string().min(5),
  token: z.string().min(1),
});

export const verify2faWithRecoveryCode = z.object({
  code: z.string().min(8),
  token: z.string().min(32),
});
