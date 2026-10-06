// 3단계: 메모 한 건 조회(GET)·수정(PUT)·삭제(DELETE)입니다.
// 주의(4단계에서 고칠 허점): 소유자 검사를 아직 하지 않아서, 로그인한 사람이면 B도 A의 메모를 읽고 고치고 지울 수 있습니다.
import { failed, isUuid, methodNotAllowed, notes, readNoteInput, reply, requireLogin, toApi } from '../_lib/notes-api.js';

export default async function handler(request, response) {
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    return methodNotAllowed(response, ['GET', 'PUT', 'DELETE']);
  }
  const login = await requireLogin(request, response);
  if (!login) return undefined;

  const id = request.query?.id;
  if (!isUuid(id)) return reply(response, 404, { error: 'NOT_FOUND' });

  try {
    if (request.method === 'GET') {
      const { data, error } = await notes().select('id, title, content').eq('id', id).maybeSingle();
      if (error) return failed(response, error);
      if (!data) return reply(response, 404, { error: 'NOT_FOUND' });
      return reply(response, 200, toApi(data));
    }

    if (request.method === 'PUT') {
      const { input, error: invalid } = readNoteInput(request, { allowId: false });
      if (invalid) return reply(response, 400, { error: invalid });
      const { data, error } = await notes()
        .update({ title: input.title, content: input.body })
        .eq('id', id)
        .select('id, title, content');
      if (error) return failed(response, error);
      if (!data?.length) return reply(response, 404, { error: 'NOT_FOUND' });
      return reply(response, 200, toApi(data[0]));
    }

    const { data, error } = await notes().delete().eq('id', id).select('id');
    if (error) return failed(response, error);
    if (!data?.length) return reply(response, 404, { error: 'NOT_FOUND' });
    return reply(response, 204);
  } catch {
    return failed(response, null);
  }
}
