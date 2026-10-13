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
const world = (extra = {}) => ({
  backups: [saved(NOTE_B, B, 'B 제목', 'B 원래 내용'), saved(NOTE_A, A, 'A 제목', 'A 내용')],
  notes: [
    { id: NOTE_B, owner_id: B, title: '바뀐 제목', content: '침해로 바뀐 내용' },
    { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' },
  ],
  ...extra,
});
const run = (repo, userId, input) => restoreNote({ userId, input, repo });

test('B가 자기 메모 한 건을 되살리면 ID·소유자·내용 해시가 사본과 같아진다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.outcome, 'restored');
  assert.deepEqual(result.body.matches, { id: true, owner: true, contentSha256: true });
  assert.equal(result.body.contentSha256, contentHash({ title: 'B 제목', content: 'B 원래 내용' }));
  const row = repo.state.notes.get(NOTE_B);
  assert.equal(row.owner_id, B);
  assert.equal(contentHash(row), repo.state.backups.get(NOTE_B).content_sha256);
});

test('다른 메모는 읽기 외에 바뀌지 않고 감사 기록은 한 줄만 늘어난다', async () => {
  const repo = fakeRepo(world());
  await run(repo, B, { id: NOTE_B });
  assert.deepEqual(repo.state.writes, [['update', NOTE_B]]);
  assert.deepEqual(repo.state.notes.get(NOTE_A), { id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' });
  assert.equal(repo.state.audit.length, 1);
  assert.deepEqual(repo.state.audit[0], { note_id: NOTE_B, owner_id: B, content_sha256: contentHash({ title: 'B 제목', content: 'B 원래 내용' }), outcome: 'restored' });
  assert.equal(JSON.stringify(repo.state.audit[0]).includes('원래 내용'), false);
});

test('B가 A의 메모 번호로 요청하면 없는 사본과 똑같이 404이고 아무것도 쓰지 않는다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_A });
  assert.equal(result.status, 404);
  assert.deepEqual(result.body, { error: 'NOT_FOUND' });
  assert.deepEqual(repo.state.writes, []);
  assert.equal(repo.state.audit.length, 0);
});

test('사본이 없는 번호는 404이다', async () => {
  const repo = fakeRepo(world());
  assert.equal((await run(repo, B, { id: OTHER })).status, 404);
});

test('A 정상 요청은 유지된다(이미 같으면 unchanged, 쓰기 없음)', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, A, { id: NOTE_A });
  assert.equal(result.status, 200);
  assert.equal(result.body.outcome, 'unchanged');
  assert.deepEqual(repo.state.writes, []);
});

test('메모가 지워졌으면 같은 ID·소유자로 다시 만든다', async () => {
  const repo = fakeRepo(world({ notes: [{ id: NOTE_A, owner_id: A, title: 'A 제목', content: 'A 내용' }] }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.body.outcome, 'created');
  assert.equal(repo.state.notes.get(NOTE_B).owner_id, B);
});

test('사본 내용이 해시와 맞지 않으면 409로 중단하고 쓰지 않는다', async () => {
  const w = world();
  w.backups[0] = { ...w.backups[0], content: '몰래 바뀐 사본' };
  const repo = fakeRepo(w);
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'BACKUP_INVALID');
  assert.deepEqual(repo.state.writes, []);
});

test('기대 해시를 보냈는데 사본과 다르면 409이다', async () => {
  const repo = fakeRepo(world());
  const result = await run(repo, B, { id: NOTE_B, contentSha256: 'a'.repeat(64) });
  assert.equal(result.status, 409);
  assert.deepEqual(repo.state.writes, []);
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

test('감사 기록 쓰기가 실패해도 복원 결과는 돌려주되 audited 가 false 이다', async () => {
  const repo = fakeRepo(world({ auditFails: true }));
  const result = await run(repo, B, { id: NOTE_B });
  assert.equal(result.status, 200);
  assert.equal(result.body.audited, false);
});

test('입력: id만 받고, 권한·다른 소유자·모르는 항목은 거부한다', () => {
  assert.deepEqual(readRestoreInput({ id: NOTE_B.toUpperCase() }, B), { input: { id: NOTE_B } });
  assert.deepEqual(readRestoreInput(JSON.stringify({ id: NOTE_B, owner_id: B }), B), { input: { id: NOTE_B } });
  assert.equal(readRestoreInput({ id: NOTE_B, owner_id: A }, B).error, 'OWNER_FORBIDDEN');
  assert.equal(readRestoreInput({ id: NOTE_B, role: 'instructor' }, B).error, 'ROLE_NOT_TRUSTED');
  assert.equal(readRestoreInput({ id: NOTE_B, title: 'x' }, B).error, 'INVALID_BODY');
  assert.equal(readRestoreInput({ id: 'export' }, B).error, 'INVALID_ID');
  assert.equal(readRestoreInput({}, B).error, 'INVALID_ID');
  assert.equal(readRestoreInput({ id: NOTE_B, contentSha256: 'zz' }, B).error, 'INVALID_HASH');
  assert.equal(readRestoreInput([], B).error, 'INVALID_BODY');
  assert.equal(readRestoreInput('not json', B).error, 'INVALID_BODY');
});
