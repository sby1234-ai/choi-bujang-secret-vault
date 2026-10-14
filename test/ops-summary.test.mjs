import assert from 'node:assert/strict';
import { test } from 'node:test';
import { maskCode, maskHash, maskId, policyVersion, practiceSummary, summarizeAudit, summarizeDevices } from '../src/ops-summary.mjs';

const HASH = 'a'.repeat(64);

test('서버 기록은 가린 모양으로만 내보낸다', () => {
  assert.equal(maskId('ccb4aa46-9fca-45a2-b53c-50ab34fff1db'), 'ccb4…f1db');
  assert.equal(maskHash(HASH), 'aaaaaaaa…');
  assert.equal(maskHash('짧음'), null);
  assert.equal(maskCode('7120-9F4C'), '71**-**4C');
  assert.equal(maskCode('bad'), '가림');
});

test('기기 요약의 개수는 같은 기록에서 센다', () => {
  const { summary, records } = summarizeDevices([
    { code: '7120-9F4C', status: 'approved', requested_at: '2026-10-14T00:35:33Z', approved_at: '2026-10-14T00:40:00Z', owner_id: 'x', token_sha256: HASH },
    { code: 'AAAA-BBBB', status: 'revoked', requested_at: '2026-10-14T01:00:00Z' },
    { code: 'CCCC-DDDD', status: 'weird' },
  ]);
  assert.deepEqual(summary, { total: 3, pending: 0, approved: 1, revoked: 1, unknown: 1 });
  assert.equal(records.length, 3);
  assert.equal(JSON.stringify(records).includes(HASH), false);
  assert.equal(JSON.stringify(records).includes('7120-9F4C'), false);
});

test('복원 기록 요약은 결과별로 세고, 일부만 받으면 truncated다', () => {
  const rows = [
    { note_id: 'ccb4aa46-9fca-45a2-b53c-50ab34fff1db', result: 'restored', before_sha256: HASH, after_sha256: HASH, at: '2026-10-13T10:00:00Z', title: '제목', content: '본문' },
    { note_id: 'ccb4aa46-9fca-45a2-b53c-50ab34fff1db', result: 'unchanged', before_sha256: HASH, after_sha256: HASH, at: '2026-10-13T10:01:00Z' },
    { note_id: '22222222-2222-4222-8222-222222222222', result: 'backup_not_found', at: '2026-10-13T10:02:00Z' },
  ];
  const all = summarizeAudit(rows, 3);
  assert.deepEqual(all.summary, { total: 3, shown: 3, byResult: { restored: 1, unchanged: 1, backup_not_found: 1 } });
  assert.equal(all.truncated, false);
  assert.equal(JSON.stringify(all).includes('본문'), false);
  assert.equal(JSON.stringify(all).includes('제목'), false);
  assert.equal(summarizeAudit(rows.slice(0, 2), 3).truncated, true);
});

test('정책 버전은 커밋 앞 12자리와 파일 개수만 보인다', () => {
  const v = policyVersion({ label: '11단계-저장점', verifiedCommit: 'b'.repeat(40), verifiedAt: '2026-10-14T09:43:40+09:00', files: { 'src/decider.mjs': HASH, 'vercel.json': HASH } });
  assert.deepEqual(v, { label: '11단계-저장점', commit: 'b'.repeat(12), verifiedAt: '2026-10-14T00:43:40.000Z', fileCount: 2, files: ['src/decider.mjs', 'vercel.json'] });
});

test('연습 결과 개수는 목록에서 센다', () => {
  assert.deepEqual(practiceSummary([{ name: 'a', passed: true }, { name: 'b', passed: false }]),
    { total: 2, passed: 1, results: [{ name: 'a', passed: true }, { name: 'b', passed: false }] });
});
