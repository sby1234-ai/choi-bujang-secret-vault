import assert from 'node:assert/strict';
import { test } from 'node:test';
import { contentHash, readRestoreInput, restoreNote } from '../src/restore-note.mjs';

const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOTE_B = '11111111-1111-4111-8111-111111111111';
const NOTE_A = '22222222-2222-4222-8222-222222222222';
const OTHER = '33333333-3333-4333-8333-333333333333';

const saved = (id, owner, title, content) => ({ id, owner_id: owner, title, content, content_sha256: contentHash({ title, content }) });
const TAMPERED = { title: '바뀐 제목', content: '침해로 바뀐 내용' };
const ORIGINAL = { title: 'B 제목', content: 'B 원래 내용' };

// 가짜 저장소: 사본 표, 메모 표, 감사 기록을 메모리에 둡니다. 쓰기(updateNote)는 바뀐 행 수를 돌려주지 않습니다.
function fakeRepo({ backups, notes, auditFails = false, noopUpdate = false }) {
  const state = { backups: new Map(backups.map(r => [r.id, r])), notes: new Map(notes.map(r => [r.id, { ...r }])), audit: [], writes: [] };
  return {
    state,
    async readBackup(id) { return state.backups.get(id) ?? null; },
    async readNote(id) { return state.notes.get(id) ? { ...state.notes.get(id) } : null; },
    async insertNote(row) {
      if (state.notes.has(row.id)) return { conflict: true };
      state.notes.set(row.id, { ...row }); state.writes.push(['insert', row.id]); return { conflict: false };
    },
    async updateNote(id, owner, fields) {
      if (noopUpdate) return undefined;
      const row = state.notes.get(id);
      if (!row || row.owner_id !== owner) return undefined;
      Object.assign(row, fields); state.writes.push(['update', id]); return undefined;
    },
    async writeAudit(entry) { if (auditFails) throw new Error('x'); state.audit.push(entry); },
  };
}
// 사본은 시험 계정 B의 메모 한 건뿐입니다.
const world = (extra = {}) => ({
  backups: [saved(NOTE_B, B, ORIGINAL.title, ORIGINAL.content)],
  notes: [
    { id: NOTE_B, owner_id: B, ...TAMPERED },
    { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' },
  ],
  ...extra,
});
const run = (repo, userId, input) => restoreNote({ userId, input, repo });
const originalHash = contentHash(ORIGINAL);

test('B가 자기 메모 한 건을 되살리면 응답은 id·restored·contentSha256 세 항목뿐이다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ['contentSha256', 'id', 'restored']);
  assert.deepEqual(result.body, { id: NOTE_B, restored: true, contentSha256: originalHash });
  const row = repo.state.notes.get(NOTE_B);
  assert.equal(row.id, NOTE_B);
  assert.equal(row.owner_id, B);
  assert.equal(contentHash(row), repo.state.backups.get(NOTE_B).content_sha256);
  assert.equal(JSON.stringify(result.body).includes('원래 내용'), false);
});

test('다른 메모는 바뀌지 않고 감사 기록은 한 줄만 늘어난다(복원 전·후 해시 포함)', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.deepEqual(repo.state.writes, [['update', NOTE_B]]);
  assert.deepEqual(repo.state.notes.get(NOTE_A), { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' });
  assert.equal(repo.state.audit.length, 1);
  assert.deepEqual(repo.state.audit[0], {
    note_id: NOTE_B, owner_id: B, before_sha256: contentHash(TAMPERED), content_sha256: originalHash, outcome: 'restored',
  });
  assert.equal(JSON.stringify(repo.state.audit[0]).includes('원래 내용'), false);
});

test('쓰기 응답에 바뀐 행 정보가 없어도, 다시 읽어 사본과 같으면 복원된 것으로 본다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.restored, true);
});

test('쓰기가 아무것도 바꾸지 못하면 500으로 멈추고 감사 기록을 남기지 않는다', async () => {
  const repo = fakeRepo(world({ noopUpdate: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'RESTORE_VERIFY_FAILED');
  assert.equal(repo.state.audit.length, 0);
});

test('B가 A의 메모 번호로 요청하면 404이고 아무것도 쓰지 않으며, 거부된 시도도 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(result.body, { error: 'NOT_FOUND' });
  assert.deepEqual(repo.state.writes, []);
  assert.deepEqual(repo.state.audit, [{ note_id: NOTE_A, owner_id: B, before_sha256: null, content_sha256: null, outcome: 'backup_not_found' }]);
});

test('사본이 없는 메모는 본인 것이어도 복원하지 않고 404이며 감사 기록에 남는다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, A, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(repo.state.writes, []);
  assert.equal((await run(repo, B, { id: OTHER })).status, 404);
  assert.deepEqual(repo.state.audit.map(row => row.outcome), ['backup_not_found', 'backup_not_found']);
});

test('A 정상 요청은 영향이 없고 사본에 없는 A 메모는 그대로이다', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.equal(repo.state.notes.get(NOTE_A).content, 'A 내용');
});

test('이미 같은 메모는 쓰지 않고 restored:false 응답과 unchanged 감사 한 줄만 남긴다', async () => {
  const w = world();
  w.notes[0] = { id: NOTE_B, owner_id: B, ...ORIGINAL };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { id: NOTE_B, restored: false, contentSha256: originalHash });
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.audit.length, 1);
  assert.equal(repo.state.audit[0].outcome, 'unchanged');
});

test('메모가 지워졌으면 같은 ID·소유자로 다시 만든다', async () => {
  const repo = fakeRepo(world({ notes: [{ id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' }] }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.restored, true);
  assert.equal(repo.state.notes.get(NOTE_B).owner_id, B);
  assert.equal(repo.state.audit[0].outcome, 'created');
  assert.equal(repo.state.audit[0].before_sha256, null);
});

test('사본 내용이 해시와 맞지 않으면 409로 중단하고 쓰지 않으며, 검증 실패를 감사 기록에 남긴다', async () => {
  const w = world();
  w.backups[0] = { ...w.backups[0], content: '몰래 바뀐 사본' };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'BACKUP_INVALID');
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.notes.get(NOTE_B).title, '바뀐 제목');
  assert.deepEqual(repo.state.audit.map(row => row.outcome), ['backup_verification_failed']);
});

test('현재 메모의 소유자가 사본과 다르면 덮어쓰지 않고 409이며 감사 기록에 남는다', async () => {
  const w = world();
  w.notes[0] = { ...w.notes[0], owner_id: A };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'OWNER_CONFLICT');
  assert.deepEqual(repo.state.writes, []);
  assert.deepEqual(repo.state.audit.map(row => row.outcome), ['owner_conflict']);
});

test('복원 성공 뒤 감사 기록을 쓰지 못하면 성공 응답을 주지 않는다', async () => {
  const repo = fakeRepo(world({ auditFails: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 500);
  assert.deepEqual(result.body, { error: 'restore_audit_failed' });
});

test('거부된 시도의 감사 기록이 실패해도 원래의 거부 응답은 그대로이다', async () => {
  const repo = fakeRepo(world({ auditFails: true }));
  const result = await run(repo, B, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(result.body, { error: 'NOT_FOUND' });
});

test('입력: id 하나만 받고 그 밖의 항목은 모두 거부한다', () => {
  assert.deepEqual(readRestoreInput({ id: NOTE_B.toUpperCase() }), { input: { id: NOTE_B } });
  assert.deepEqual(readRestoreInput(JSON.stringify({ id: NOTE_B })), { input: { id: NOTE_B } });
  assert.equal(readRestoreInput({ id: NOTE_B, owner_id: B }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, role: 'instructor' }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, title: 'x' }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: NOTE_B, dryRun: true }).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ noteId: NOTE_B }).error, 'INVALID_ID');
  assert.equal(readRestoreInput({ id: 'export' }).error, 'INVALID_ID');
  assert.equal(readRestoreInput({}).error, 'INVALID_ID');
  assert.equal(readRestoreInput([]).error, 'INVALID_BODY');
  assert.equal(readRestoreInput('not json').error, 'INVALID_BODY');
});
