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
import { and, between, eq, sql } from "drizzle-orm";
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

type CreateVerificationCodeData = Pick<VerificationCode, "user_id" | "type">;

export const createVerificationCode = async (
  data: CreateVerificationCodeData,
) => {
  const validPeriod = getEnv("OTP_EXPIRES_IN");
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
      expired_at: createDate(validPeriod),
      type: data.type,
    })
    .returning();

  return { verifyCode, encoded: token, otp };
};

export const getVerificationCode = async (
  token: string,
  type: VerificationEnum,
) => {
  let key = token;
  if (key.length > getEnv("OTP_LENGTH")) {
    const [token, err] = await tryit(
      verifyToken<{ otp: string }>(key, getEnv("ENCRYPTION_KEY")),
    );

    if (err) {
      return;
    }

    key = token.otp;
  }

  const totp = new TOTPController({
    digits: getEnv("OTP_LENGTH"),
    period: getEnv("OTP_EXPIRES_IN"),
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

  const [verifyCode] = await db
    .select()
    .from(verificationCodeTable)
    .where(
      and(
        eq(verificationCodeTable.code, code),
        eq(verificationCodeTable.type, type),
      ),
    );

  return verifyCode;
};

export const removeVerificationCode = async (
  key: string,
  type: VerificationEnum,
) => {
  const [removed] = await db
    .delete(verificationCodeTable)
    .where(
      and(
        eq(verificationCodeTable.code, key),
        eq(verificationCodeTable.type, type),
      ),
    )
    .returning();

  return !!removed;
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
