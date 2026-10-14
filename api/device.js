// 11단계: 이 브라우저의 기기 승인 상태 보기(GET)와 승인 요청(POST)입니다.
// 로그인이 필요하고, 승인 여부는 서버(DB의 devices 표)가 정합니다. 승인 요청은 "승인 대기"로 등록만 하며 권한을 주지 않습니다.
// 응답에는 상태와(대기 중일 때만) 확인 코드만 담고, 기기 증표는 HttpOnly 쿠키로만 보냅니다.
import { deviceStatus, requestDevice } from './_lib/device-api.js';
import { methodNotAllowed, reply, requireLogin } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return methodNotAllowed(response, ['GET', 'POST']);
  }
  const login = await requireLogin(request, response);
  if (!login) return undefined;
  try {
    const result = request.method === 'GET'
      ? await deviceStatus(request, login)
      : await requestDevice(request, response, login);
    return reply(response, 200, result);
  } catch {
    console.error('device request failed');
    return reply(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
  }
}
