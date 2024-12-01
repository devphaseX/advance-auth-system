import { db } from "@/db/init.js";
import {
  verificationCodeTable,
  type VerificationCode,
} from "@/db/schemas/verification_codes_table.js";
import { sha256 } from "@oslojs/crypto/sha2";
import { decodeBase32IgnorePadding, decodeBase64 } from "@oslojs/encoding";
import { env, getEnv } from "config/env/index.js";
import { generateHOTP } from "oslo/otp";
import { HMAC } from "oslo/crypto";
import { encodeBase32NoPadding } from "@oslojs/encoding";
import { VerificationEnum } from "@/commons/enums/verification.enum";
import { and, between, eq, SQL, sql } from "drizzle-orm";
import { encryptString } from "@/commons/utils/encryption";
import {
  generateRandomOTP,
  generateRandomRecoveryCode,
} from "@/commons/utils/code";
import { TOTPController } from "oslo/otp";
import { createDate, TimeSpan } from "oslo";
import { differenceInSeconds } from "date-fns";
import { signToken, verifyToken } from "@/commons/utils/token";
import tryit from "@/commons/utils/tryit";

type CreateVerificationCodeData = Pick<VerificationCode, "user_id" | "type"> & {
  expires_in?: TimeSpan;
};

export const createVerificationCode = async (
  data: CreateVerificationCodeData,
  metadata?: Record<string, any>,
) => {
  const validPeriod = data.expires_in ?? getEnv("OTP_EXPIRES_IN");
  const tot = new TOTPController({
    digits: getEnv("OTP_LENGTH"),
    period: validPeriod,
  });
  const otp = await tot.generate(
    new TextEncoder().encode(getEnv("ENCRYPTION_KEY")),
  );

  const { token } = await signToken(
    { otp },
    getEnv("ENCRYPTION_KEY"),
    validPeriod,
  );

  const [verifyCode] = await db
    .insert(verificationCodeTable)
    .values({
      code: Buffer.from(sha256(new TextEncoder().encode(otp))).toString("hex"),
      user_id: data.user_id,
      metadata,
      expired_at: createDate(validPeriod),
      type: data.type,
    })
    .returning();

  return { verifyCode, encoded: token, otp };
};

export const getVerificationCode = async (
  token: string,
  type: VerificationEnum,
  userId?: string,
) => {
  let key = token;
  let period: TimeSpan;
  if (key.length > getEnv("OTP_LENGTH")) {
    const [token, err] = await tryit(
      verifyToken<{ otp: string; exp: number; iat: number }>(
        key,
        getEnv("ENCRYPTION_KEY"),
      ),
    );

    if (err) {
      return;
    }

    period = new TimeSpan(token.exp - token.iat, "s");
    key = token.otp;
  }

  period ??= getEnv("OTP_EXPIRES_IN");

  const totp = new TOTPController({
    digits: getEnv("OTP_LENGTH"),
    period,
  });

  const isValid = await totp.verify(
    key,
    new TextEncoder().encode(getEnv("ENCRYPTION_KEY")),
  );

  if (!isValid) {
    return null;
  }

  const code = Buffer.from(sha256(new TextEncoder().encode(key))).toString(
    "hex",
  );

  const query: SQL[] = [
    eq(verificationCodeTable.code, code),
    eq(verificationCodeTable.type, type),
  ];

  if (userId) {
    query.push(eq(verificationCodeTable.user_id, userId));
  }

  const [verifyCode] = await db
    .select()
    .from(verificationCodeTable)
    .where(and(...query));

  return verifyCode;
};

export const removeVerificationCode = async (id: string, userId: string) => {
  const [removed] = await db
    .delete(verificationCodeTable)
    .where(
      and(
        eq(verificationCodeTable.user_id, userId),
        eq(verificationCodeTable.id, id),
      ),
    )
    .returning();

  return !!removed;
};

export const invalidateVerificationCodes = async (
  userId: string,
  type: VerificationEnum,
) => {
  await db
    .delete(verificationCodeTable)
    .where(
      and(
        eq(verificationCodeTable.user_id, userId),
        eq(verificationCodeTable.type, type),
      ),
    );
};

export const getVerificationCodeAttemptWithin = async (
  userId: string,
  type: VerificationEnum,
  timeInterval: TimeSpan,
) => {
  const [{ count }] = await db
    .select({ count: sql<number>`count(*)` })
    .from(verificationCodeTable)
    .where(
      and(
        eq(verificationCodeTable.user_id, userId),
        between(
          verificationCodeTable.created_at,
          createDate(timeInterval),
          new Date(),
        ),
      ),
    );

  return count;
};
