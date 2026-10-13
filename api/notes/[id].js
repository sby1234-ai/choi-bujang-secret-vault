// 메모 한 건 조회(GET)·수정(PUT)·삭제(DELETE)입니다.
// 4단계: 모든 질의에 서버가 확인한 사용자 ID의 owner_id 조건을 붙입니다.
// 남의 메모는 없는 메모와 똑같이 404로 답해서 그 번호가 존재하는지도 알려 주지 않습니다.
// 수정은 기존 행의 소유자가 본인일 때만 되고, 새 행의 owner_id도 본인 ID로 고정합니다(소유자 변경 불가).
import { failed, isUuid, logDenied, methodNotAllowed, notes, ownsRow, readNoteInput, rejectInput, reply, requireLogin, toApi } from '../_lib/notes-api.js';

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
      const { data, error } = await notes()
        .select('id, owner_id, title, content')
        .eq('id', id)
        .eq('owner_id', login.userId)
        .maybeSingle();
      if (error) return failed(response, error);
      if (!data) { logDenied('not_found_or_not_owner'); return reply(response, 404, { error: 'NOT_FOUND' }); }
      // 질의 조건과 별개로 저장된 소유자를 한 번 더 대조합니다. 다르면 없는 메모와 똑같이 404 입니다.
      if (!ownsRow(login, data)) { logDenied('owner_mismatch'); return reply(response, 404, { error: 'NOT_FOUND' }); }
      return reply(response, 200, toApi(data));
    }

    // 수정·삭제는 바꾸기 전에 저장된 소유자를 먼저 읽어 검증된 사용자와 대조합니다(아래 질의의 owner_id 조건은 그대로 둡니다).
    const { data: current, error: readError } = await notes().select('id, owner_id').eq('id', id).maybeSingle();
    if (readError) return failed(response, readError);
    if (!current) { logDenied('not_found_or_not_owner'); return reply(response, 404, { error: 'NOT_FOUND' }); }
    if (!ownsRow(login, current)) { logDenied('owner_mismatch'); return reply(response, 404, { error: 'NOT_FOUND' }); }

    if (request.method === 'PUT') {
      const { input, error: invalid } = readNoteInput(request, { allowId: false, userId: login.userId });
      if (invalid) return rejectInput(response, invalid);
      const { data, error } = await notes()
        .update({ title: input.title, content: input.body, owner_id: login.userId })
        .eq('id', id)
        .eq('owner_id', login.userId)
        .select('id, title, content');
      if (error) return failed(response, error);
      if (!data?.length) return reply(response, 404, { error: 'NOT_FOUND' });
      return reply(response, 200, toApi(data[0]));
    }

    const { data, error } = await notes()
      .delete()
      .eq('id', id)
      .eq('owner_id', login.userId)
      .select('id');
    if (error) return failed(response, error);
    if (!data?.length) return reply(response, 404, { error: 'NOT_FOUND' });
    return reply(response, 204);
  } catch {
    return failed(response, null);
  }
}
