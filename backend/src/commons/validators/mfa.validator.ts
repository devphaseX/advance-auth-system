import { z } from "zod";

export const verifyMfaSetupSchema = z.object({
  secret: z.string().base64(),
  code: z.string().min(5),
});
