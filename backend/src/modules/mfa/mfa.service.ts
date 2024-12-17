import { decrypt, encrypt } from "@/commons/utils/encryption";
import { db } from "@/db/init";
import { userPreferenceTable } from "@/db/schemas";
import { decodeBase64, encodeBase64 } from "@oslojs/encoding";
import { eq } from "drizzle-orm";

export const setMfaSecret = async (userId: string, secret: string) => {
  const [updatedPref] = await db
    .update(userPreferenceTable)
    .set({
      enabled_2fa: true,
      two_factor_secret: secret,
    })
    .where(eq(userPreferenceTable.user_id, userId))
    .returning();

  return !!updatedPref;
};

export const removeMfaSecret = async (userId: string) => {
  const [updatedPref] = await db
    .update(userPreferenceTable)
    .set({
      enabled_2fa: false,
      two_factor_secret: null,
      recovery_codes: null,
    })
    .where(eq(userPreferenceTable.user_id, userId))
    .returning();

  return !!updatedPref;
};

export function decryptMfaRecoveryCodes(encryptedRecoveryCodes: string[]) {
  return encryptedRecoveryCodes.map((encryptedCode) =>
    new TextDecoder().decode(decrypt(decodeBase64(encryptedCode))),
  );
}

export function encryptedMfaRecoveryCodes(recoveryCodes: string[]) {
  return recoveryCodes.map((code) =>
    encodeBase64(encrypt(new TextEncoder().encode(code))),
  );
}
