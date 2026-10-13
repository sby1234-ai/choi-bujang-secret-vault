import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  AUDIT_PATH, MANIFEST_PATH, applyRestore, buildManifest, changeSetId, comparePolicy, formatPlan, loadVerifiedPolicy,
} from '../scripts/policy-lib.mjs';

// 가짜 저장소: 임시 폴더에 git 저장소를 만들고, 정책 파일 몇 개를 저장점 커밋으로 남깁니다. 실제 저장소·DB·배포에는 닿지 않습니다.
const FILES = [{ path: 'src/rules.mjs' }, { path: 'api/list.js' }, { path: 'aleph.config.json', policyKeys: ['allowedRoutes', 'originalApiUrl'] }];
const CONFIG = { step: 9, publicAppUrl: 'https://example.invalid', allowedRoutes: ['GET /api/notes', 'POST /api/notes'], originalApiUrl: 'https://example.invalid/rest/v1/notes' };

const run = (root, ...args) => execFileSync('git', ['-C', root, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args], { stdio: 'pipe' }).toString().trim();

function makeRepo() {
  const root = mkdtempSync(join(tmpdir(), 'policy-test-'));
  run(root, 'init', '-q');
  mkdirSync(join(root, 'src'));
  mkdirSync(join(root, 'api'));
  writeFileSync(join(root, 'src/rules.mjs'), 'export const RULE_IDS = ["a", "b"];\n');
  writeFileSync(join(root, 'api/list.js'), 'export default () => 1;\n');
  writeFileSync(join(root, 'aleph.config.json'), `${JSON.stringify(CONFIG, null, 2)}\n`);
  writeFileSync(join(root, 'other.txt'), '사본 목록에 없는 파일\n');
  run(root, 'add', '.');
  run(root, 'commit', '-q', '-m', '저장점');
  const commit = run(root, 'rev-parse', 'HEAD');
  buildManifest({ root, commit, files: FILES, label: '시험용 저장점' });
  return { root, commit };
}
const done = (root) => rmSync(root, { recursive: true, force: true });
const read = (root, path) => readFileSync(join(root, path), 'utf8');
const state = (root) => {
  const policy = loadVerifiedPolicy(root);
  const results = comparePolicy(policy, root);
  return { policy, results, id: changeSetId(policy.manifest, results) };
};

test('정책이 사본과 같으면 모든 파일이 같음이고 되돌릴 항목이 없다', () => {
  const { root } = makeRepo();
  try {
    const { policy, results } = state(root);
    assert.deepEqual(results.map((item) => item.status), ['same', 'same', 'same']);
    const { lines, changed } = formatPlan(policy, results, root);
    assert.equal(changed.length, 0);
    assert.ok(lines.some((line) => line.includes('사본 검증: 통과 (3개 파일 지문 일치)')));
    assert.equal(applyRestore({ root, confirm: 'none' }).wrote, false);
  } finally { done(root); }
});

test('미리보기는 복원할 버전과 바뀔 항목을 보여 주고 아무것도 바꾸지 않는다', () => {
  const { root, commit } = makeRepo();
  try {
    writeFileSync(join(root, 'src/rules.mjs'), 'export const RULE_IDS = [];\n');
    rmSync(join(root, 'api/list.js'));
    const { policy, results } = state(root);
    const { lines, changed } = formatPlan(policy, results, root);
    const text = lines.join('\n');
    assert.ok(text.includes(`커밋 ${commit.slice(0, 12)}`));
    assert.ok(text.includes('시험용 저장점'));
    assert.ok(text.includes('변경됨  src/rules.mjs'));
    assert.ok(text.includes('삭제됨  api/list.js'));
    assert.equal(changed.length, 2);
    assert.equal(read(root, 'src/rules.mjs'), 'export const RULE_IDS = [];\n');
    assert.equal(existsSync(join(root, 'api/list.js')), false);
  } finally { done(root); }
});

test('확인 번호가 없거나 틀리면 아무것도 쓰지 않고 중단한다', () => {
  const { root } = makeRepo();
  try {
    writeFileSync(join(root, 'src/rules.mjs'), 'tampered\n');
    assert.throws(() => applyRestore({ root, confirm: undefined }), /확인 번호가 맞지 않습니다/u);
    assert.throws(() => applyRestore({ root, confirm: '000000000000' }), /확인 번호가 맞지 않습니다/u);
    assert.equal(read(root, 'src/rules.mjs'), 'tampered\n');
    assert.equal(existsSync(join(root, AUDIT_PATH)), false);
  } finally { done(root); }
});

test('맞는 확인 번호로 다시 읽어 검증한 뒤 사본으로 되돌리고 감사 기록을 한 줄 덧붙인다', () => {
  const { root, commit } = makeRepo();
  try {
    writeFileSync(join(root, 'src/rules.mjs'), 'tampered\n');
    rmSync(join(root, 'api/list.js'));
    const { id } = state(root);
    const result = applyRestore({ root, confirm: id, now: new Date('2026-10-13T00:00:00Z') });
    assert.equal(result.wrote, true);
    assert.equal(read(root, 'src/rules.mjs'), 'export const RULE_IDS = ["a", "b"];\n');
    assert.equal(read(root, 'api/list.js'), 'export default () => 1;\n');
    const lines = read(root, AUDIT_PATH).trim().split('\n');
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.verifiedCommit, commit);
    assert.deepEqual(entry.files.map((file) => file.path).sort(), ['api/list.js', 'src/rules.mjs']);
    assert.equal(JSON.stringify(entry).includes('tampered'), false);
    assert.deepEqual(state(root).results.map((item) => item.status), ['same', 'same', 'same']);
    assert.equal(applyRestore({ root, confirm: id }).wrote, false);
  } finally { done(root); }
});

test('설정 파일은 정책 항목만 사본 값으로 바꾸고 단계·주소 같은 다른 설정은 지금 값을 유지한다', () => {
  const { root } = makeRepo();
  try {
    const config = { ...CONFIG, step: 10, restoreRoute: 'POST /api/notes/restore', allowedRoutes: ['GET /api/notes', 'DELETE /api/notes/:id'] };
    writeFileSync(join(root, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
    const { results, id } = state(root);
    assert.deepEqual(results[2].changedKeys, ['allowedRoutes']);
    applyRestore({ root, confirm: id });
    const after = JSON.parse(read(root, 'aleph.config.json'));
    assert.deepEqual(after.allowedRoutes, CONFIG.allowedRoutes);
    assert.equal(after.step, 10);
    assert.equal(after.restoreRoute, 'POST /api/notes/restore');
  } finally { done(root); }
});

test('설정 파일에서 정책이 아닌 항목만 다르면 같음으로 본다', () => {
  const { root } = makeRepo();
  try {
    writeFileSync(join(root, 'aleph.config.json'), `${JSON.stringify({ ...CONFIG, step: 10, restoreRoute: 'x' }, null, 2)}\n`);
    assert.equal(state(root).results[2].status, 'same');
  } finally { done(root); }
});

test('사본 목록의 지문이 커밋의 파일과 다르면 검증 실패로 중단하고 아무것도 쓰지 않는다', () => {
  const { root } = makeRepo();
  try {
    const manifest = JSON.parse(read(root, MANIFEST_PATH));
    manifest.files['src/rules.mjs'] = 'f'.repeat(64);
    writeFileSync(join(root, MANIFEST_PATH), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileSync(join(root, 'api/list.js'), 'tampered\n');
    assert.throws(() => loadVerifiedPolicy(root), /사본 검증 실패: src\/rules\.mjs/u);
    assert.throws(() => applyRestore({ root, confirm: 'x' }), /사본 검증 실패/u);
    assert.equal(read(root, 'api/list.js'), 'tampered\n');
    assert.equal(existsSync(join(root, AUDIT_PATH)), false);
  } finally { done(root); }
});

test('사본 목록이 없거나 형식이 틀리거나 커밋이 없으면 중단한다', () => {
  const { root } = makeRepo();
  try {
    const original = read(root, MANIFEST_PATH);
    const manifest = JSON.parse(original);
    writeFileSync(join(root, MANIFEST_PATH), `${JSON.stringify({ ...manifest, verifiedCommit: 'a'.repeat(40) })}\n`);
    assert.throws(() => loadVerifiedPolicy(root), /사본 커밋 .* 찾을 수 없습니다/u);
    writeFileSync(join(root, MANIFEST_PATH), `${JSON.stringify({ ...manifest, schema: 'other' })}\n`);
    assert.throws(() => loadVerifiedPolicy(root), /형식이 맞지 않습니다/u);
    writeFileSync(join(root, MANIFEST_PATH), 'not json');
    assert.throws(() => loadVerifiedPolicy(root), /읽을 수 없습니다/u);
    rmSync(join(root, MANIFEST_PATH));
    assert.throws(() => loadVerifiedPolicy(root), /사본 목록.*없습니다/u);
  } finally { done(root); }
});

test('목록의 경로가 폴더 밖을 가리키거나 지문 모양이 틀리면 거부한다', () => {
  const { root } = makeRepo();
  try {
    const manifest = JSON.parse(read(root, MANIFEST_PATH));
    writeFileSync(join(root, MANIFEST_PATH), `${JSON.stringify({ ...manifest, files: { '../outside.txt': 'a'.repeat(64) } })}\n`);
    assert.throws(() => loadVerifiedPolicy(root), /형식이 맞지 않습니다/u);
    writeFileSync(join(root, MANIFEST_PATH), `${JSON.stringify({ ...manifest, files: { 'src/rules.mjs': 'short' } })}\n`);
    assert.throws(() => loadVerifiedPolicy(root), /형식이 맞지 않습니다/u);
  } finally { done(root); }
});

test('미리보기 뒤에 파일이 또 바뀌면 확인 번호가 달라져 적용이 중단된다', () => {
  const { root } = makeRepo();
  try {
    writeFileSync(join(root, 'src/rules.mjs'), 'first change\n');
    const { id } = state(root);
    writeFileSync(join(root, 'src/rules.mjs'), 'second change\n');
    assert.throws(() => applyRestore({ root, confirm: id }), /확인 번호가 맞지 않습니다/u);
    assert.equal(read(root, 'src/rules.mjs'), 'second change\n');
  } finally { done(root); }
});

test('사본 목록에 없는 파일과 기존 감사 기록 줄은 건드리지 않는다', () => {
  const { root } = makeRepo();
  try {
    mkdirSync(join(root, 'policy'), { recursive: true });
    appendFileSync(join(root, AUDIT_PATH), '{"earlier":true}\n');
    writeFileSync(join(root, 'other.txt'), '바뀐 다른 파일\n');
    writeFileSync(join(root, 'src/rules.mjs'), 'tampered\n');
    applyRestore({ root, confirm: state(root).id });
    assert.equal(read(root, 'other.txt'), '바뀐 다른 파일\n');
    const lines = read(root, AUDIT_PATH).trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(lines[0], '{"earlier":true}');
  } finally { done(root); }
});

test('Windows의 줄 끝(CRLF) 변환만 다른 파일은 같음으로 본다', () => {
  const { root } = makeRepo();
  try {
    writeFileSync(join(root, 'src/rules.mjs'), 'export const RULE_IDS = ["a", "b"];\r\n');
    assert.equal(state(root).results[0].status, 'same');
  } finally { done(root); }
});

test('이미 있는 사본 목록은 덮어쓰지 않는다', () => {
  const { root, commit } = makeRepo();
  try {
    assert.throws(() => buildManifest({ root, commit, files: FILES }), /덮어쓰지 않습니다/u);
    assert.throws(() => buildManifest({ root, commit: 'nope', files: FILES, force: true }), /찾을 수 없습니다/u);
  } finally { done(root); }
});
