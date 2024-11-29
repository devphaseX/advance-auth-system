import { z } from "zod";
import { Hook } from "@hono/zod-validator";
import { errorResponse } from "./api_response";
import { Env, ValidationTargets } from "hono";
import StatusCodes from "http-status";
import { ErrorCode } from "../enums/error_code";

export const formatError = (error: z.ZodError) => {
  return error.issues.map((err) => ({
    field: err.path.join("."),
    message: err.message,
  }));
};

export const validateErrorHook =
  <
    T,
    E extends Env,
    P extends string,
    Target extends keyof ValidationTargets = keyof ValidationTargets,
    O = {},
  >(
    message: string,
  ): Hook<T, E, P, Target, O> =>
  (result, c) => {
    if (!result.success) {
      return errorResponse(c, message, StatusCodes.BAD_REQUEST, {
        error_code: ErrorCode.VALIDATION_ERROR,
        errors: formatError(result.error),
      });
    }
  };
