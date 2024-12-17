import { z, type TypeOf } from "zod";
import { createInsertSchema } from "drizzle-zod";
import { userTable } from "@/db/schemas/users_table.js";
import { VerifyCodeType } from "../enums/verify_code";
import { getEnv } from "config/env";

export const registerUserSchema = createInsertSchema(userTable, {
  name: z.string().min(1).max(255),
  email: z.string().email(),
})
  .pick({ name: true, email: true })
  .extend({
    password: z.string().min(8),
    confirmPassword: z.string(),
    userAgent: z.string().optional(),
  })
  .refine(({ confirmPassword, password }) => confirmPassword === password, {
    message: "password not a match",
    path: ["confirmPassword"],
  });

export const loginUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  userAgent: z.string().optional(),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1).optional(),
});

export const verifyEmailSchema = z.object({
  code: z.string().min(1).max(255),
});

export const resetPasswordSchema = z.object({
  password: z.string().min(8),
  sessionId: z.string().min(12),
});

export const forgetPasswordSchema = z.object({ email: z.string().email() });
export const verifyForgetPasswordCodeSchema = z
  .union([
    z.object({
      type: z.enum([VerifyCodeType.OTP]),
      otp: z.string().length(getEnv("OTP_LENGTH")),
    }),
    z.object({
      type: z.enum([VerifyCodeType.TOKEN]),
      token: z.string().min(12),
    }),
  ])
  .and(z.object({ sessionId: z.string().min(12) }));

export const resetPassword2faSchema = z.object({
  code: z.string().min(5),
  sessionId: z.string().min(12),
});

export const resetPasswordWithRecoveryCodeSchema = z.object({
  code: z.string().min(5),
  sessionId: z.string().min(12),
});

export type ResetPasswordWithRecoveryCode = TypeOf<
  typeof resetPasswordWithRecoveryCodeSchema
>;

export const getRecoveryCodesSchema = z.object({ password: z.string().min(1) });

export const requestChangeEmailSchema = z.object({ email: z.string().email() });
export const confirmChangeEmailSchema = z.object({ code: z.string().min(6) });
