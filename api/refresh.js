// POST /api/refresh — 만료가 가까운 로그인 토큰을 갱신 토큰으로 새로 받습니다.
// 11단계: 갱신 토큰은 본문이 아니라 HttpOnly 쿠키에서만 읽고, 새 토큰도 쿠키로만 보냅니다. 화면을 다시 열 때 로그인 상태 확인에도 씁니다.
import { REFRESH_COOKIE, clearSessionCookies, publicAuthClient, readCookie, setSessionCookies, toSession, unavailable } from './_lib/auth-api.js';
import { methodNotAllowed, reply } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const client = publicAuthClient();
  if (!client) return reply(response, 500, { error: 'SERVER_NOT_CONFIGURED' });

  const token = readCookie(request, REFRESH_COOKIE) ?? '';
  if (!token || token.length > 512) return reply(response, 401, { error: 'LOGIN_REQUIRED' });

  try {
    const { data: result, error } = await client.auth.refreshSession({ refresh_token: token });
    if (error || !result?.session) {
      clearSessionCookies(response);
      return reply(response, 401, { error: 'LOGIN_REQUIRED' });
    }
    setSessionCookies(response, result.session);
    return reply(response, 200, toSession(result.session));
  } catch {
    return unavailable(response);
  }
}
