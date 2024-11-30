import { encodeBase32UpperCaseNoPadding, encodeBase64 } from "@oslojs/encoding";
import { getEnv } from "config/env";
import crypto from "crypto";

export function generateRandomOTP(): string {
  const bytes = new Uint8Array(5);
  crypto.getRandomValues(bytes);
  const code = encodeBase32UpperCaseNoPadding(bytes);
  return code;
}

export function generateRandomRecoveryCode(): string {
  const recoveryCodeBytes = new Uint8Array(10);
  crypto.getRandomValues(recoveryCodeBytes);
  const recoveryCode = encodeBase32UpperCaseNoPadding(recoveryCodeBytes);
  return recoveryCode;
}

export function generate2faSecret(): [string, Uint8Array] {
  const bytes = new Uint8Array(getEnv("TWO_FACTOR_SECRET_LENGTH"));
  crypto.getRandomValues(bytes);
  return [encodeBase64(bytes), bytes];
}
