import assert from 'node:assert/strict';
import { test } from 'node:test';
import { contentHash, readRestoreInput, restoreNote } from '../src/restore-note.mjs';

const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOTE_B = '11111111-1111-4111-8111-111111111111';
const NOTE_A = '22222222-2222-4222-8222-222222222222';
const OTHER = '33333333-3333-4333-8333-333333333333';

const saved = (id, owner, title, content) => ({ id, owner_id: owner, title, content, content_sha256: contentHash({ title, content }) });

// 가짜 저장소: 사본 표, 메모 표, 감사 기록을 메모리에 둡니다.
function fakeRepo({ backups, notes, auditFails = false }) {
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
      const row = state.notes.get(id);
      if (!row || row.owner_id !== owner) return 0;
      Object.assign(row, fields); state.writes.push(['update', id]); return 1;
    },
    async writeAudit(entry) { if (auditFails) throw new Error('x'); state.audit.push(entry); },
  };
}
// 사본은 시험 계정 B의 메모 한 건뿐입니다.
const world = (extra = {}) => ({
  backups: [saved(NOTE_B, B, 'B 제목', 'B 원래 내용')],
  notes: [
    { id: NOTE_B, owner_id: B, title: '바뀐 제목', content: '침해로 바뀐 내용' },
    { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' },
  ],
  ...extra,
});
const run = (repo, userId, input) => restoreNote({ userId, input, repo });

test('B가 자기 메모 한 건을 되살리면 응답은 id·restored·contentSha256 세 항목뿐이다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ['contentSha256', 'id', 'restored']);
  assert.deepEqual(result.body, { id: NOTE_B, restored: true, contentSha256: contentHash({ title: 'B 제목', content: 'B 원래 내용' }) });
  const row = repo.state.notes.get(NOTE_B);
  assert.equal(row.owner_id, B);
  assert.equal(contentHash(row), repo.state.backups.get(NOTE_B).content_sha256);
  assert.equal(JSON.stringify(result.body).includes('원래 내용'), false);
});

test('다른 메모는 바뀌지 않고 감사 기록은 한 줄만 늘어난다', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.deepEqual(repo.state.writes, [['update', NOTE_B]]);
  assert.deepEqual(repo.state.notes.get(NOTE_A), { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' });
  assert.equal(repo.state.audit.length, 1);
  assert.deepEqual(repo.state.audit[0], { note_id: NOTE_B, owner_id: B, content_sha256: contentHash({ title: 'B 제목', content: 'B 원래 내용' }), outcome: 'restored' });
  assert.equal(JSON.stringify(repo.state.audit[0]).includes('원래 내용'), false);
});

test('B가 A의 메모 번호로 요청하면 404이고 아무것도 쓰지 않는다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(result.body, { error: 'NOT_FOUND' });
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.audit.length, 0);
});

test('사본이 없는 메모는 본인 것이어도 복원하지 않고 404이다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, A, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(repo.state.writes, []);
  assert.equal((await run(repo, B, { id: OTHER })).status, 404);
});

test('A 정상 요청은 영향이 없고 사본에 없는 A 메모는 그대로이다', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.equal(repo.state.notes.get(NOTE_A).content, 'A 내용');
});

test('이미 같은 메모는 쓰지 않고 restored 응답과 unchanged 감사 한 줄만 남긴다', async () => {
  const w = world();
  w.notes[0] = { id: NOTE_B, owner_id: B, title: 'B 제목', content: 'B 원래 내용' };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.audit[0].outcome, 'unchanged');
});

test('메모가 지워졌으면 같은 ID·소유자로 다시 만든다', async () => {
  const repo = fakeRepo(world({ notes: [{ id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' }] }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(repo.state.notes.get(NOTE_B).owner_id, B);
  assert.equal(repo.state.audit[0].outcome, 'created');
});

test('사본 내용이 해시와 맞지 않으면 409로 중단하고 쓰지 않는다', async () => {
  const w = world();
  w.backups[0] = { ...w.backups[0], content: '몰래 바뀐 사본' };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'BACKUP_INVALID');
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.notes.get(NOTE_B).title, '바뀐 제목');
});

test('현재 메모의 소유자가 사본과 다르면 덮어쓰지 않고 409이다', async () => {
  const w = world();
  w.notes[0] = { ...w.notes[0], owner_id: A };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'OWNER_CONFLICT');
  assert.deepEqual(repo.state.writes, []);
});

test('감사 기록 쓰기가 실패해도 복원 결과 응답은 같은 세 항목이다', async () => {
  const repo = fakeRepo(world({ auditFails: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body).sort(), ['contentSha256', 'id', 'restored']);
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
