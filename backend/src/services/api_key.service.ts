import { withPagination } from "@/commons/utils/paginate";
import {
  DeactivateApiKeyPayload,
  RotateApiKeyPayload,
} from "@/commons/validators/api_key.validator";
import { db } from "@/db/init";
import { ApiKey, apiKeyTable, CreateApiKeyPayload } from "@/db/schemas";
import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase64NoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { getEnv } from "config/env";
import { desc, eq } from "drizzle-orm";
import _generateApiKey from "generate-api-key";
import { Context } from "hono";
import { createDate, TimeSpan } from "oslo";
import { scheduleApiKeyDeletion } from "trigger/schedule_api_key_deletion";

export enum ApiScopeKey {
  NOTIFY_WEBHOOK = "notify:webhook",
}

export interface ApiResourceScope {
  resource: string;
  description?: string;
  scopes: Array<ApiScope>;
}

export interface ApiScope {
  key: ApiScopeKey;
  description?: string;
}

export const apiScopes: Array<ApiResourceScope> = [
  {
    resource: "webhook",
    scopes: [{ key: ApiScopeKey.NOTIFY_WEBHOOK }],
  },
];

export interface ApiKeyParams {
  fullKey: string; // Complete API key including prefix and checksum
  rawKey: string; // The raw random key without prefix/checksum
  prefix: string; // Environment prefix (e.g., prod_, dev_)
  checksum: string; // Checksum for validation
}

export class InvalidApiKeyError extends Error {}

export function generateApiKey() {
  const prefix = getEnv("API_PREFIX");
  const apiKeyBytes = _generateApiKey({
    prefix,
    length: getEnv("API_KEY_LENGTH"),
    dashes: false,
    method: "bytes",
  });

  const apiKeyWithPrefix = apiKeyBytes.toString();
  const [, rawKey] = apiKeyWithPrefix.split(getEnv("API_DELIMITER"));
  const checksum = generateKeyCheckSum(rawKey, prefix);
  const fullKey = `${apiKeyWithPrefix}${getEnv("API_DELIMITER")}${checksum}`;

  return {
    key: fullKey,
    prefix,
    hash: hashApiKey(apiKeyWithPrefix),
    checksum,
    rawKey,
  };
}

function generateKeyCheckSum(key: string, apiPrefix: string) {
  const hashBytes = sha256(new TextEncoder().encode(`${key}${apiPrefix}`));
  return encodeBase64NoPadding(hashBytes).slice(
    0,
    getEnv("API_CHECKSUM_LENGTH"),
  );
}

export function validateApiKey(apiKey: string) {
  try {
    const apiPrefix = getEnv("API_PREFIX");
    const checksumLength = getEnv("API_CHECKSUM_LENGTH");
    const apiDelimiter = getEnv("API_DELIMITER");
    //the value 2 stands for the delimiter character used between the prefix and checksum
    const minApiKeyLength =
      apiPrefix.length + getEnv("API_CHECKSUM_LENGTH") + 2;
    if (apiKey.length < minApiKeyLength) {
      return false;
    }

    const keyWithChecksum = apiKey.slice(apiPrefix.length + 1);
    if (keyWithChecksum.length <= checksumLength) {
      return false;
    }

    const [key, extractedChecksum] = keyWithChecksum.split(apiDelimiter);
    const expectedChecksum = generateKeyCheckSum(key, apiPrefix);
    return expectedChecksum === extractedChecksum;
  } catch {}

  return false;
}

function extractApiKeyComponents(apiKey: string) {
  if (!validateApiKey(apiKey)) {
    throw new InvalidApiKeyError("Invalid api key");
  }

  const apiDelimiter = getEnv("API_DELIMITER");
  const [prefix, rawKey, checksum] = apiKey.split(apiDelimiter);

  return {
    key: apiKey,
    prefix,
    checksum,
    rawKey,
  };
}

function hashApiKey(apiKey: string) {
  return encodeHexLowerCase(sha256(new TextEncoder().encode(apiKey)));
}

export async function createApiKey(payload: CreateApiKeyPayload) {
  const { key, prefix, hash } = generateApiKey();
  const apiDurations =
    payload.expires_in == null || Math.sign(payload.expires_in) === -1
      ? {
          expires_in: payload.expires_in,
          expired_at: createDate(new TimeSpan(payload.expires_in!, "s")),
        }
      : null;
  const [apiKey] = await db
    .insert(apiKeyTable)
    .values({
      name: payload.name,
      hash,
      replaces_key_id: payload.replaces_key_id ?? null,
      prefix,
      ...apiDurations,
    })
    .returning();

  return { apiKey, key };
}

export const getApiKeys = async (c: Context, userId?: string) => {
  return withPagination(
    c,
    db
      .select()
      .from(apiKeyTable)
      .where(userId ? eq(apiKeyTable.user_id, userId) : undefined)
      .orderBy(desc(apiKeyTable.created_at))
      .$dynamic(),
  );
};

export const getApiKeyById = async (id: string) => {
  const [apiKey] = await db
    .select()
    .from(apiKeyTable)
    .where(eq(apiKeyTable.id, id))
    .limit(1);

  return apiKey;
};

export const getApiKeyByHash = async (key: string) => {
  const hash = hashApiKey(key);
  const [apiKey] = await db
    .select()
    .from(apiKeyTable)
    .where(eq(apiKeyTable.hash, hash))
    .limit(1);
  return apiKey;
};

type DeactivateApiKeyParams = DeactivateApiKeyPayload & {
  deletedBy: string;
};

export async function deactivateApiKey(
  id: string,
  options: DeactivateApiKeyParams,
) {
  return db.transaction(async () => {
    const now = new Date();

    const gracePeriod =
      new TimeSpan(options.gracePeriod, "s") ??
      new TimeSpan(getEnv("API_DELETE_GRACE_PERIOD_DAYS"), "d");

    const deletionDate = options.immediately ? now : createDate(gracePeriod);

    const [apiKey] = await db
      .update(apiKeyTable)
      .set({
        deleted_at: deletionDate,
        deleted_reason: options.deletedReason,
        deleted_by: options.deletedBy,
        is_active: options.immediately ? false : true,
      })
      .where(eq(apiKeyTable.id, id))
      .returning();

    if (typeof options.immediately === "boolean" && !options.immediately) {
      await scheduleApiKeyDeletion.trigger(
        { keyId: id },
        { delay: deletionDate },
      );
    }

    return apiKey;
  });
}

export async function rotateApiKey(
  apiKey: ApiKey,
  payload: RotateApiKeyPayload,
) {
  return db.transaction(async () => {
    const newApiKey = await createApiKey({
      name: apiKey.name,
      scopes: apiKey.scopes,
      expires_in: apiKey.expires_in,
      replaces_key_id: apiKey.id,
    });

    const rotationWindowEnds = createDate(
      new TimeSpan(payload.rotatationPeriods, "s"),
    );

    await db
      .update(apiKeyTable)
      .set({
        replaced_by_key_id: newApiKey.apiKey.id,
        rotation_window_ends: rotationWindowEnds,
      })
      .where(eq(apiKeyTable.id, apiKey.id));

    return newApiKey;
  });
}
