// 10단계: 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 POST /api/notes/restore 입니다.
// 로그인한 본인의 메모 사본만 되살릴 수 있고(소유자는 검증된 토큰에서만 얻습니다), 본문에는 메모 번호(id)만 받습니다.
// 사본의 ID·소유자·내용 해시를 대조하고, 다른 메모는 건드리지 않으며, 감사 기록은 한 줄만 덧붙입니다.
import { failed, methodNotAllowed, reply, requireLogin } from '../_lib/notes-api.js';
import { restoreRepo } from '../_lib/restore-repo.js';
import { readRestoreInput, restoreNote } from '../../src/restore-note.mjs';

const log = (reason) => console.warn(`notes restore denied: ${reason}`);

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  const { input, error } = readRestoreInput(request.body, login.userId);
  if (error === 'ROLE_NOT_TRUSTED' || error === 'OWNER_FORBIDDEN') {
    log(error === 'ROLE_NOT_TRUSTED' ? 'role_in_body' : 'owner_in_body');
    return reply(response, 403, { error });
  }
  if (error) return reply(response, 400, { error });

  try {
    const result = await restoreNote({ userId: login.userId, input, repo: restoreRepo(), log });
    return reply(response, result.status, result.body);
  } catch {
    return failed(response, null);
  }
}
