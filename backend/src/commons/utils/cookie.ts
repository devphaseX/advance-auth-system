import { Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { JwtToken } from "./token";
import { getEnv } from "config/env";
import { AppEnv } from "../enums/env.enum";

export const setAuthenicationCookie = (
  c: Context,
  token: { access: JwtToken; refresh?: JwtToken },
) => {
  setCookie(c, getEnv("ACCESS_TOKEN_COOKIE_NAME"), token.access.token, {
    maxAge: token.access.expiresIn.seconds(),
    secure: getEnv("NODE_ENV") === AppEnv.PRODUCTION,
    httpOnly: true,
    sameSite: getEnv("NODE_ENV") === AppEnv.PRODUCTION ? "Strict" : "Lax",
    path: "/",
  });

  if (token.refresh) {
    setCookie(c, getEnv("REFRESH_TOKEN_COOKIE_NAME"), token.refresh.token, {
      maxAge: token.refresh.expiresIn.seconds(),
      secure: getEnv("NODE_ENV") === AppEnv.PRODUCTION,
      httpOnly: true,
      sameSite: getEnv("NODE_ENV") === AppEnv.PRODUCTION ? "Strict" : "Lax",
      path: getEnv("REFRESH_PATH"),
    });
  }
};

export const clearAuthenicationCookie = (c: Context) => {
  const now = new Date();
  deleteCookie(c, getEnv("ACCESS_TOKEN_COOKIE_NAME"), {
    secure: getEnv("NODE_ENV") === AppEnv.PRODUCTION,
    httpOnly: true,
    sameSite: getEnv("NODE_ENV") === AppEnv.PRODUCTION ? "Strict" : "Lax",
    path: "/",
  });

  deleteCookie(c, getEnv("REFRESH_TOKEN_COOKIE_NAME"), {
    secure: getEnv("NODE_ENV") === AppEnv.PRODUCTION,
    httpOnly: true,
    sameSite: getEnv("NODE_ENV") === AppEnv.PRODUCTION ? "Strict" : "Lax",
    path: getEnv("REFRESH_PATH"),
  });
};

export const getRefreshTokenCookie = (c: Context) =>
  getCookie(c, getEnv("REFRESH_TOKEN_COOKIE_NAME"));

export const getAccessTokenCookie = (c: Context) =>
  getCookie(c, getEnv("ACCESS_TOKEN_COOKIE_NAME"));
