import { db } from "@/db/init.js";
import { userPreferenceTable } from "@/db/schemas/user_preferences.js";
import { userTable, type User } from "@/db/schemas/users_table.js";
import { eq } from "drizzle-orm";

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
        created_at: userTable.created_at,
        updated_at: userTable.updated_at,
      });

    await db.insert(userPreferenceTable).values({
      user_id: newUser.id,
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

export const getUserWithPassword = async (email: string) => {
  const [user] = await db
    .select()
    .from(userTable)
    .where(eq(userTable.email, email));
  return user;
};
