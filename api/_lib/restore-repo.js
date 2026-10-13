// 메모 복원이 쓰는 저장소 접근입니다. 서버 전용 키는 환경변수에서만 읽고, 응답·로그에 넣지 않습니다.
// notes_backup(사본)은 읽기만, notes는 복원 대상 한 건만, notes_restore_audit(감사 기록)는 덧붙이기만 합니다.
import { createClient } from '@supabase/supabase-js';
import { notes } from './notes-api.js';

let database;
const client = () => {
  database ??= createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return database;
};

export function restoreRepo() {
  return {
    async readBackup(id) {
      const { data, error } = await client().from('notes_backup')
        .select('id, owner_id, title, content, content_sha256, backed_up_at').eq('id', id).maybeSingle();
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
      const { error } = await client().from('notes_restore_audit').insert(entry);
      if (error) throw error;
    },
  };
}
