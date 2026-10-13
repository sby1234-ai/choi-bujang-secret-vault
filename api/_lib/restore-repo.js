// 메모 복원이 쓰는 저장소 접근입니다. 서버 전용 키는 환경변수에서만 읽고, 응답·로그에 넣지 않습니다.
// notes_backup(사본)은 읽기만, notes는 복원 대상 한 건만, notes_restore_audit(감사 기록)는 덧붙이기만 합니다.
// 연결은 요청마다 새로 만들고, fetch도 호출하는 순간의 globalThis.fetch를 씁니다(이전 요청의 연결·상태를 재사용하지 않습니다).
import { createClient } from '@supabase/supabase-js';

const liveFetch = (...args) => globalThis.fetch(...args);

function connect() {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { fetch: liveFetch },
  });
}

export function restoreRepo() {
  const db = connect();
  const notes = () => db.from('notes');
  return {
    async readBackup(id) {
      const { data, error } = await db.from('notes_backup')
        .select('id, owner_id, title, content, content_sha256').eq('id', id).maybeSingle();
      if (error) throw error;
      return data;
    },
    async readNote(id) {
      const { data, error } = await notes().select('id, owner_id, title, content').eq('id', id).maybeSingle();
      if (error) throw error;
      return data;
    },
    async insertNote(row) {
      const { error } = await notes().insert(row);
      if (error?.code === '23505') return { conflict: true };
      if (error) throw error;
      return { conflict: false };
    },
    async updateNote(id, ownerId, fields) {
      const { data, error } = await notes().update({ ...fields, owner_id: ownerId })
        .eq('id', id).eq('owner_id', ownerId).select('id');
      if (error) throw error;
      return data?.length ?? 0;
    },
    async writeAudit(entry) {
      const { error } = await db.from('notes_restore_audit').insert(entry);
      if (error) throw error;
    },
  };
}
