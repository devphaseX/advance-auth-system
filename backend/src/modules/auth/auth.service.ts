import { generateRandomRecoveryCode } from "@/commons/utils/code";
import { encryptString } from "@/commons/utils/encryption";
import { db } from "@/db/init.js";
import {
  publicUserPreference,
  PublicUserPreference,
  UserPreference,
  userPreferenceTable,
} from "@/db/schemas/user_preferences.js";
import { userTable, type User } from "@/db/schemas/users_table.js";
import { encodeBase64 } from "@oslojs/encoding";
import { eq, ilike, SQL, sql } from "drizzle-orm";

type CreateUserData = Pick<
  User,
  "name" | "email" | "password_hash" | "password_salt"
>;

export async function createUser(data: CreateUserData) {
  return db.transaction(async () => {
    const [newUser] = await db
      .insert(userTable)
      .values({
        name: data.name,
        email: data.email,
        password_hash: data.password_hash,
        password_salt: data.password_salt,
      })
      .returning({
        id: userTable.id,
        name: userTable.name,
        email: userTable.email,
        email_verified_at: userTable.email_verified_at,
        created_at: userTable.created_at,
        updated_at: userTable.updated_at,
      });

    const recoveryCodes = Array(5)
      .fill(0)
      .map(() => {
        const code = generateRandomRecoveryCode();
        return encodeBase64(encryptString(code));
      });

    await db.insert(userPreferenceTable).values({
      user_id: newUser.id,
      recovery_codes: recoveryCodes,
    });

    return newUser;
  });
}

export const checkEmailAvailability = async (email: string) => {
  const [userExist] = await db
    .select()
    .from(userTable)
    .where(eq(userTable.email, email));

  return Boolean(userExist);
};

export const getClientUserPayload = async (
  params: Partial<{ id: string; email: string }>,
) => {
  if (!Object.keys(params).length) {
    throw new Error("no params provided");
  }

  const query: SQL[] = [];

  if (params.id) {
    query.push(eq(userTable.id, params.id));
  }

  if (params.email) {
    query.push(ilike(userTable.email, params.email));
  }

  const [user] = await db
    .select({
      id: userTable.id,
      name: userTable.name,
      email: userTable.email,
      email_verified_at: userTable.email_verified_at,
      preference: sql<PublicUserPreference>`row_to_json(${publicUserPreference})`,
      created_at: userTable.created_at,
      updated_at: userTable.updated_at,
    } satisfies Partial<Record<keyof User, unknown> & { preference: unknown }>)
    .from(userTable)
    .innerJoin(
      publicUserPreference,
      eq(publicUserPreference.user_id, userTable.id),
    )
    .where(sql.join(query, " OR "));

  return user;
};

export const getUser = async (
  params: Partial<{ id: string; email: string }>,
) => {
  if (!Object.keys(params).length) {
    throw new Error("no params provided");
  }

  const query: SQL[] = [];

  if (params.id) {
    query.push(eq(userTable.id, params.id));
  }

  if (params.email) {
    query.push(ilike(userTable.email, params.email));
  }

  const [user] = await db
    .select({
      id: userTable.id,
      name: userTable.name,
      email: userTable.email,
      email_verified_at: userTable.email_verified_at,
      preference: sql<UserPreference>`row_to_json(${userPreferenceTable})`,
      password_hash: userTable.password_hash,
      password_salt: userTable.password_salt,
      created_at: userTable.created_at,
      updated_at: userTable.updated_at,
    } satisfies Partial<Record<keyof User, unknown> & { preference: unknown }>)
    .from(userTable)
    .innerJoin(
      userPreferenceTable,
      eq(userPreferenceTable.user_id, userTable.id),
    )
    .where(sql.join(query, " OR "));

  return user;
};

export const markUserEmailAsVerified = async (userId: string) => {
  const [verifiedUser] = await db
    .update(userTable)
    .set({
      email_verified_at: new Date(),
    })
    .where(eq(userTable.id, userId))
    .returning();

  return getClientUserPayload({ id: verifiedUser.id });
};

export const updateUserPassword = async (
  userId: string,
  passwordHash: string,
  passwordSaltByte: Buffer,
) => {
  const passwordSalt = passwordSaltByte.toString("base64");

  const [updatedUser] = await db
    .update(userTable)
    .set({
      password_hash: passwordHash,
      password_salt: passwordSalt,
    })
    .where(eq(userTable.id, userId))
    .returning();

  return Boolean(updatedUser);
};

export type AuthUser = Awaited<ReturnType<typeof getUser>>;

export const resetRecoveryCodes = async (
  userId: string,
  recoveryCodes: string[],
) => {
  const [updatePref] = await db
    .update(userPreferenceTable)
    .set({ recovery_codes: recoveryCodes })
    .where(eq(userPreferenceTable.user_id, userId))
    .returning();

  return !!updatePref;
};
