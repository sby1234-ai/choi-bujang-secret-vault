// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 POST /api/notes/restore 입니다.
// 10단계 복원 묶음: 사본을 다시 읽어 검증하고(실패하면 중단), 실행 전에 버전·바뀔 항목을 보여 주며, 한 건만 ID·소유자·내용 해시로 대조해 되살리는 경로의 일부입니다.
// 로그인한 본인의 메모 사본만 되살릴 수 있고(소유자는 검증된 토큰에서만 얻습니다), 본문에는 메모 번호(id) 하나만 받고, 다른 항목은 400입니다.
// 사본의 ID·소유자·내용 해시를 대조하고, 다른 메모는 건드리지 않으며, 감사 기록은 시도마다 한 줄씩 덧붙입니다(거부된 시도 포함).
import { reply, requireLogin } from '../_lib/notes-api.js';
import { restoreRepo } from '../_lib/restore-repo.js';
import { readRestoreInput, restoreNote } from '../../src/restore-note.mjs';

const RESOURCE_ID = 'notes.own';
const log = (reason) => console.warn(`notes restore: ${reason}`);

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return reply(response, 405, { error: 'method_not_allowed' });
  }
  // 이 경로가 다루는 자원은 로그인한 본인의 메모(notes.own)입니다.
  response.setHeader('X-Resource-Id', RESOURCE_ID);
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  const { input, error } = readRestoreInput(request.body);
  if (error) return reply(response, 400, { error: 'invalid_restore_request' });

  try {
    const result = await restoreNote({ userId: login.userId, input, repo: restoreRepo(), log });
    return reply(response, result.status, result.body);
  } catch {
    return reply(response, 500, { error: 'restore_unavailable' });
  }
}
