export type JwtPayload = { [key: string]: unknown };

export interface JwtAccessPayload extends JwtPayload {
  user_id: string;
  session_id: string;
}

export interface Jwt2faAccessPayload extends JwtPayload {
  email: string;
  user_agent?: string;
  required_2fa: boolean;
}

export interface JwtRefreshPayload extends JwtPayload {
  session_id: string;
}

export interface JwtRequestEmailChangePayload extends JwtPayload {
  email: string;
}

export interface JwtPasswordResetPayload extends JwtPayload {
  session_id: string;
}
