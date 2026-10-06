// POST /api/logout — 로그인한 요청의 세션을 서버가 끝냅니다. 토큰 검사는 다른 API와 같은 도우미가 합니다.
import { adminAuthClient } from './_lib/auth-api.js';
import { methodNotAllowed, reply, requireLogin } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  const token = String(request.headers.authorization ?? '').replace(/^Bearer\s+/iu, '');
  try {
    await adminAuthClient().auth.admin.signOut(token);
  } catch {
    // 세션 종료에 실패해도 화면은 토큰을 지웁니다. 토큰은 곧 만료됩니다.
    console.error('logout request failed');
  }
  return reply(response, 204);
}
