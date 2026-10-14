// POST /api/logout — 로그인한 요청의 세션을 서버가 끝냅니다. 토큰 검사는 다른 API와 같은 도우미가 합니다.
import { ACCESS_COOKIE, adminAuthClient, clearSessionCookies, readCookie } from './_lib/auth-api.js';
import { methodNotAllowed, reply, requireLogin } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const login = await requireLogin(request, response);
  if (!login) { clearSessionCookies(response); return undefined; }

  const header = String(request.headers.authorization ?? '').replace(/^Bearer\s+/iu, '');
  const token = header || readCookie(request, ACCESS_COOKIE) || '';
  try {
    await adminAuthClient().auth.admin.signOut(token);
  } catch {
    // 세션 종료에 실패해도 화면은 토큰을 지웁니다. 토큰은 곧 만료됩니다.
    console.error('logout request failed');
  }
  clearSessionCookies(response);
  return reply(response, 204);
}
