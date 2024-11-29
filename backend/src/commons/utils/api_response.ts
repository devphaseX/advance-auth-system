import type { ErrorCode } from "commons/enums/error_code.js";
import { type Context } from "hono";
import { type StatusCode } from "hono/utils/http-status";
import StatusCodes from "http-status";

type ApiBaseResponse = {
  success: boolean;
  message?: string;
};

export type ApiSuccessResponse<Data = unknown> = {
  success: true;
} & ApiBaseResponse &
  Data;

export type ApiErrorResponse = {
  success: false;
  error_code?: ErrorCode;
  message: string;
  errors: Record<string, unknown> | Error;
} & ApiBaseResponse;

export function successResponse<
  Data = unknown,
  Code extends StatusCode = (typeof StatusCodes)["OK"],
>(c: Context, data?: Data, code?: Code, message?: string) {
  return c.json(
    <ApiSuccessResponse<Data>>{ success: true, message, ...data },
    code ?? StatusCodes.OK,
  );
}

export function errorResponse<
  Code extends StatusCode = (typeof StatusCodes)["INTERNAL_SERVER_ERROR"],
>(
  c: Context,
  message: string,
  code?: Code,
  options?: {
    error_code?: ErrorCode;
    errors?: Record<string, unknown> | Error;
  },
) {
  const { error_code, errors } = options ?? {};
  return c.json(
    <ApiErrorResponse>{ success: false, message, error_code, errors },
    code ?? StatusCodes.INTERNAL_SERVER_ERROR,
  );
}
