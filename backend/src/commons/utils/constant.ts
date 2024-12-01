import { TimeSpan } from "oslo";

export const FORGET_PASSWORD_ALLOWED_ATTEMPT = 3;
export const FORGET_PASSWORD_ALLOWED_ATTEMPT_DURATION = new TimeSpan(10, "m");
export const REQUEST_CHANGE_EMAIL_ATTEMPT = 3;
export const REQUEST_CHANGE_EMAIL_ALLOWED_ATTEMPT_DURATION = new TimeSpan(
  10,
  "m",
);
export const VERIFY_EMAIL_EXPIRES_IN = new TimeSpan(45, "m");
export const FORGET_PASSWORD_OTP_EXPIRES_IN = new TimeSpan(45, "m");
