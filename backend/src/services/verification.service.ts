import { db } from "@/db/init.js";
import {
  verificationCodeTable,
  type VerificationCode,
} from "@/db/schemas/verification_codes_table.js";
import { sha256 } from "@oslojs/crypto/sha2";
import { decodeBase64 } from "@oslojs/encoding";
import { env } from "config/env/index.js";
import { generateHOTP } from "oslo/otp";
import { HMAC } from "oslo/crypto";
import { encodeBase32NoPadding } from "@oslojs/encoding";

type CreateVerificationCodeData = Pick<
  VerificationCode,
  "user_id" | "type" | "expired_at"
>;

export const createVerificationCode = async (
  data: CreateVerificationCodeData,
) => {
  const key = await new HMAC("SHA-256").generateKey();
  const code = encodeBase32NoPadding(new Uint8Array(key));

  const [vCode] = await db
    .insert(verificationCodeTable)
    .values({
      code: code,
      user_id: data.user_id,
      expired_at: data.expired_at,
      type: data.type,
    })
    .returning();

  return [vCode, code];
};
