// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 POST /api/notes/restore 입니다.
// 로그인한 본인의 메모 사본만 되살릴 수 있고(소유자는 검증된 토큰에서만 얻습니다), 본문에는 메모 번호(id) 하나만 받고, 다른 항목은 400입니다.
// 사본의 ID·소유자·내용 해시를 대조하고, 다른 메모는 건드리지 않으며, 감사 기록은 한 줄만 덧붙입니다.
// 점검용 로그: 요청마다 방식·본문 키 이름·응답 상태·메모 번호 앞 8글자만 한 줄 남깁니다(토큰·메모 내용·소유자는 남기지 않습니다).
import { failed, methodNotAllowed, reply, requireLogin } from '../_lib/notes-api.js';
import { restoreRepo } from '../_lib/restore-repo.js';
import { readRestoreInput, restoreNote } from '../../src/restore-note.mjs';

const log = (reason) => console.warn(`notes restore denied: ${reason}`);

function bodyKeys(body) {
  let data = body;
  if (typeof data === 'string') { try { data = JSON.parse(data); } catch { return 'unparsable'; } }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'not_object';
  return Object.keys(data).slice(0, 8).join(',').slice(0, 80);
}

export default async function handler(request, response) {
  const seen = { method: request.method, keys: bodyKeys(request.body), id: '' };
  const done = (status, extra = '') => console.log(`restore-trace ${JSON.stringify({ ...seen, status, extra })}`);

  if (request.method !== 'POST') { done(405); return methodNotAllowed(response, ['POST']); }
  const login = await requireLogin(request, response);
  if (!login) { done(401); return undefined; }

  const { input, error } = readRestoreInput(request.body);
  if (error) { done(400, error); return reply(response, 400, { error }); }
  seen.id = input.id.slice(0, 8);

  try {
    const result = await restoreNote({ userId: login.userId, input, repo: restoreRepo(), log });
    done(result.status, result.body.error ?? `restored=${result.body.restored}`);
    return reply(response, result.status, result.body);
  } catch {
    done(502, 'exception');
    return failed(response, null);
  }
}
