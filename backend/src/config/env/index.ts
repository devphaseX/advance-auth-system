import { AppEnv } from "commons/enums/env.enum.js";
import "dotenv/config";
import { z, type TypeOf } from "zod";
import { type TimeSpanUnit } from "oslo";
import {
  isSupportedTimeUnit,
  parseStrTimeUnit,
} from "commons/utils/time_unit.js";

export const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  PORT: z.coerce.number(),
  NODE_ENV: z.nativeEnum(AppEnv),
  APP_ORIGIN: z.string().url(),
  AUTH_SECRET: z.string().min(12),
  BASE_PATH: z.string().min(1),
  OTP_EXPIRES_IN: z
    .string()
    .refine(isSupportedTimeUnit, { message: "invalid time unit value" })
    .transform((value) => parseStrTimeUnit(value)!),
  AUTH_EXPIRES_IN: z
    .string()
    .refine(isSupportedTimeUnit, { message: "invalid time unit value" })
    .transform((value) => parseStrTimeUnit(value)!),
  ENCRYPTION_KEY: z.string().min(1),
  AUTH_REFRESH_SECRET: z.string().min(12),
  AUTH_REFRESH_EXPIRES_IN: z
    .string()
    .refine(isSupportedTimeUnit, { message: "invalid time unit value" })
    .transform((value) => parseStrTimeUnit(value)!),

  ACCESS_TOKEN_COOKIE_NAME: z.string().min(1),
  REFRESH_TOKEN_COOKIE_NAME: z.string().min(1),
  REFRESH_PATH: z.string().min(1),
  OTP_LENGTH: z.coerce.number().min(5),
  MAIL_TRAP_API_KEY: z.string().min(1),
  MAIL_SENDER_EMAIL: z.string().email(),
  MAIL_SENDER_NAME: z.string().min(1),
  MAIL_TRAP_ACCOUNT_ID: z.string().min(1),
  TWO_FACTOR_SECRET_LENGTH: z.coerce.number().int(),
  PLATFORM_NAME: z.string().min(1),
  TWO_FACTOR_AUTH_SECRET: z.string().min(16),
  TWO_FACTOR_AUTH_SECRET_EXPIRES_IN: z
    .string()
    .refine(isSupportedTimeUnit, { message: "invalid time unit value" })
    .transform((value) => parseStrTimeUnit(value)!),
});

export const formatErrors = (
  errors: z.ZodFormattedError<{ [key: string]: any }, string>,
) =>
  Object.entries(errors)
    .map(([name, value]) => {
      if (value && "_errors" in value)
        return `${name}: ${value._errors.join(", ")}\n`;
    })
    .filter(Boolean);

const result = envSchema.safeParse(process.env);

if (!result.success) {
  const formattedError = result.error.format();
  throw new Error(
    `Invalid environment variables:\n${formatErrors(formattedError as any).join("")}`,
  );
}
export const env = envSchema.parse(process.env);
type Env = TypeOf<typeof envSchema>;

declare global {
  namespace NodeJS {
    interface ProcessEnv extends Env, Dict<any> {}
  }
}

export function getEnv<Key extends keyof Env>(key: Key): Env[Key] {
  return env[key];
}
