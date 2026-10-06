// 로그인·토큰 갱신·로그아웃을 서버 함수 한곳에서 처리하는 도우미입니다. (api/_lib 아래 파일은 주소로 열리지 않습니다.)
// 공식 SDK(signInWithPassword, refreshSession, admin.signOut)만 쓰고, 비밀번호나 토큰을 직접 만들지 않습니다.
// 공개용(publishable) 키는 서버 환경변수 SUPABASE_PUBLISHABLE_KEY에서만 읽습니다. 화면 코드에는 키가 없습니다.
// 비밀번호·이메일·토큰은 로그에 남기지 않습니다.
import { createClient } from '@supabase/supabase-js';
import { reply } from './notes-api.js';

export function publicAuthClient() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_PUBLISHABLE_KEY) return null;
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_PUBLISHABLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

export function adminAuthClient() {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export function readJsonBody(request) {
  let data = request.body;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return null; }
  }
  return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
}

// 화면에 필요한 값만 돌려줍니다.
export const toSession = (session) => ({
  access_token: session.access_token,
  refresh_token: session.refresh_token,
  expires_at: session.expires_at,
  email: session.user?.email ?? null,
});

// SDK 오류 코드를 화면용 오류 이름으로 바꿉니다. 원문 메시지는 돌려주지 않습니다.
export function loginFailed(response, error) {
  const names = {
    invalid_credentials: ['INVALID_LOGIN', 401],
    email_not_confirmed: ['EMAIL_NOT_CONFIRMED', 401],
    user_banned: ['USER_BANNED', 401],
    over_request_rate_limit: ['RATE_LIMITED', 429],
  };
  const [name, status] = names[error?.code] ?? ['LOGIN_FAILED', 401];
  return reply(response, status, { error: name });
}

export const unavailable = (response) => {
  console.error('auth request failed');
  return reply(response, 502, { error: 'AUTH_UNAVAILABLE' });
};
