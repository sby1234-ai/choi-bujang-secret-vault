// POST /api/login — 이메일·비밀번호 로그인을 서버가 대신 처리합니다.
// 11단계: 토큰은 HttpOnly 쿠키로만 보내고, 응답 본문에는 만료 시각과 이메일만 담습니다.
import { loginFailed, publicAuthClient, readJsonBody, setSessionCookies, toSession, unavailable } from './_lib/auth-api.js';
import { methodNotAllowed, reply } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const client = publicAuthClient();
  if (!client) return reply(response, 500, { error: 'SERVER_NOT_CONFIGURED' });

  const data = readJsonBody(request);
  const email = typeof data?.email === 'string' ? data.email.trim() : '';
  const password = typeof data?.password === 'string' ? data.password : '';
  if (!email || email.length > 254 || !password || password.length > 256) {
    return reply(response, 401, { error: 'INVALID_LOGIN' });
  }

  try {
    const { data: result, error } = await client.auth.signInWithPassword({ email, password });
    if (error || !result?.session) return loginFailed(response, error);
    setSessionCookies(response, result.session);
    return reply(response, 200, toSession(result.session));
  } catch {
    return unavailable(response);
  }
}
