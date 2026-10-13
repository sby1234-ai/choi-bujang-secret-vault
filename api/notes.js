// 로그인한 사용자의 메모 목록(GET)과 추가(POST)입니다.
// 목록은 서버가 확인한 사용자 ID의 메모만 돌려주고, 추가할 때 owner_id는 항상 그 ID로 저장합니다(본문의 owner_id는 쓰지 않습니다).
import { failed, logDenied, methodNotAllowed, notes, ownsRow, readNoteInput, rejectInput, reply, requireLogin, toApi } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return methodNotAllowed(response, ['GET', 'POST']);
  }
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  try {
    if (request.method === 'GET') {
      const { data, error } = await notes()
        .select('id, owner_id, title, content')
        .eq('owner_id', login.userId)
        .order('created_at', { ascending: true });
      if (error) return failed(response, error);
      // 질의 조건과 별개로, 돌려줄 행마다 저장된 소유자를 검증된 사용자와 다시 대조합니다. 다른 소유자의 행은 응답에서 뺍니다.
      const rows = data ?? [];
      const own = rows.filter((row) => ownsRow(login, row));
      if (own.length !== rows.length) logDenied('owner_mismatch_row');
      return reply(response, 200, own.map(toApi));
    }

    const { input, error: invalid } = readNoteInput(request, { allowId: true, userId: login.userId });
    if (invalid) return rejectInput(response, invalid);
    const id = input.id ?? crypto.randomUUID();
    const { error } = await notes().insert({
      id, owner_id: login.userId, title: input.title, content: input.body,
    });
    if (error?.code === '23505') return reply(response, 409, { error: 'ID_EXISTS' });
    if (error) return failed(response, error);
    return reply(response, 201, { id });
  } catch {
    return failed(response, null);
  }
}
