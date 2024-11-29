import { Argon2id } from "oslo/password";
import { randomBytes } from "crypto";

export async function hash(payload: string, salt?: Buffer) {
  if (salt && salt.length < 12) {
    throw new TypeError("salt must be more than 12 bytes");
  }

  salt = randomBytes(12);

  const argon = new Argon2id({
    secret: salt,
  });

  const hash = await argon.hash(payload);

  return {
    hash,
    salt,
  };
}

export function verify(payload: string, hash: string, secret: Buffer) {
  const argon = new Argon2id({ secret });
  return argon.verify(hash, payload);
}
