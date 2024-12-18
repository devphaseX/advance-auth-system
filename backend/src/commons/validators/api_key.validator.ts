import { TypeOf, z } from "zod";

export const deactivateApiKeySchema = z.object({
  immediately: z.boolean().optional(),
  gracePeriod: z.number().int(),
  deletedReason: z.string().optional(),
});

export type DeactivateApiKeyPayload = TypeOf<typeof deactivateApiKeySchema>;

export const rotateApiKeySchema = z.object({
  rotatationPeriods: z.number().int(),
});

export type RotateApiKeyPayload = TypeOf<typeof rotateApiKeySchema>;
