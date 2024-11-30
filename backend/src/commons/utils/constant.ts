import { TimeSpan } from "oslo";

export const FORGET_PASSWORD_ALLOWED_ATTEMPT = 3;
export const FORGET_PASSWORD_ALLOWED_ATTEMPT_DURATION = new TimeSpan(10, "m");
