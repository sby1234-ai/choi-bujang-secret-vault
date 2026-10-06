// POST /api/refresh — 만료가 가까운 로그인 토큰을 갱신 토큰으로 새로 받습니다.
import { publicAuthClient, readJsonBody, toSession, unavailable } from './_lib/auth-api.js';
import { methodNotAllowed, reply } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const client = publicAuthClient();
  if (!client) return reply(response, 500, { error: 'SERVER_NOT_CONFIGURED' });

  const data = readJsonBody(request);
  const token = typeof data?.refresh_token === 'string' ? data.refresh_token : '';
  if (!token || token.length > 512) return reply(response, 401, { error: 'LOGIN_REQUIRED' });

  try {
    const { data: result, error } = await client.auth.refreshSession({ refresh_token: token });
    if (error || !result?.session) return reply(response, 401, { error: 'LOGIN_REQUIRED' });
    return reply(response, 200, toSession(result.session));
  } catch {
    return unavailable(response);
  }
}
