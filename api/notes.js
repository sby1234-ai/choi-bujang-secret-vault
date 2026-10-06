// 3단계: 로그인한 사용자의 메모 목록(GET)과 추가(POST)입니다.
// 아직 소유자 검사는 하지 않습니다: 한 건 조회·수정·삭제(/api/notes/:id)는 누구의 메모든 접근합니다(4단계에서 막을 허점).
import { failed, methodNotAllowed, notes, readNoteInput, reply, requireLogin, toApi } from './_lib/notes-api.js';

export default async function handler(request, response) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return methodNotAllowed(response, ['GET', 'POST']);
  }
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  try {
    if (request.method === 'GET') {
      const { data, error } = await notes()
        .select('id, title, content')
        .eq('owner_id', login.userId)
        .order('created_at', { ascending: true });
      if (error) return failed(response, error);
      return reply(response, 200, (data ?? []).map(toApi));
    }

    const { input, error: invalid } = readNoteInput(request, { allowId: true });
    if (invalid) return reply(response, 400, { error: invalid });
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
