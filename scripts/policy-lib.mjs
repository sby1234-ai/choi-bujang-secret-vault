// 10단계: 검증된 정책 사본 목록(policy/verified-policy.json)을 읽어 검증하고, 지금의 정책 파일과 비교해 되돌리는 공통 함수입니다.
// 사본의 원본은 통과한 저장점 커밋(verifiedCommit)입니다. 목록의 지문(sha256)이 그 커밋에서 꺼낸 파일의 지문과 같을 때만 사본으로 인정합니다.
// 사본이 없거나 형식·커밋·지문 검증에 실패하면 예외로 멈추고, 아무것도 바꾸지 않습니다.
// 학습 DB·배포 같은 실제 운영 정책에는 접속하지 않고, 작업 폴더의 정책 파일만 다룹니다.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export const defaultRoot = resolve(import.meta.dirname, '..');
export const MANIFEST_PATH = 'policy/verified-policy.json';
export const AUDIT_PATH = 'policy/restore-audit.log';
export const SCHEMA = 'vault.policy.verified.v1';

const COMMIT = /^[0-9a-f]{40}$/u;
const HASH = /^[0-9a-f]{64}$/u;
const KEY = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

const fail = (message) => { throw new Error(message); };
export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const toLf = (buffer) => Buffer.from(buffer.toString('utf8').replace(/\r\n/gu, '\n'), 'utf8');

export function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'buffer', timeout: 15000, maxBuffer: 8 * 1024 * 1024, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
  });
}

// 키 순서가 달라도 같은 값이면 같은 문자열이 되게 만듭니다.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}
const subsetOf = (json, keys) => canonical(Object.fromEntries(keys.map((key) => [key, json?.[key] ?? null])));

// 사본 목록의 한 파일 항목은 지문 문자열이거나 { sha256, policyKeys }입니다. policyKeys는 JSON 설정에서 정책으로 보는 항목 이름입니다.
function readEntries(manifest) {
  if (!manifest || typeof manifest !== 'object' || manifest.schema !== SCHEMA || !COMMIT.test(manifest.verifiedCommit ?? '')
      || !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) {
    fail(`${MANIFEST_PATH}의 형식이 맞지 않습니다.`);
  }
  const entries = Object.entries(manifest.files).map(([path, value]) => ({
    path,
    hash: typeof value === 'string' ? value : value?.sha256,
    policyKeys: typeof value === 'string' ? null : (value?.policyKeys ?? null),
  }));
  const badPath = (path) => path.includes('..') || path.startsWith('/') || path.includes('\\') || path.length > 200;
  const badKeys = (entry) => entry.policyKeys !== null && (!Array.isArray(entry.policyKeys) || !entry.policyKeys.length
    || !entry.policyKeys.every((key) => KEY.test(key)) || !entry.path.endsWith('.json'));
  if (!entries.length || entries.some((entry) => !HASH.test(entry.hash ?? '') || badPath(entry.path) || badKeys(entry))) {
    fail(`${MANIFEST_PATH}의 형식이 맞지 않습니다.`);
  }
  return entries;
}

// 사본 목록을 읽을 때마다 처음부터 다시 검증합니다(앞서 검증한 결과를 재사용하지 않습니다).
export function loadVerifiedPolicy(root = defaultRoot) {
  const file = join(root, MANIFEST_PATH);
  if (!existsSync(file)) fail(`검증된 정책 사본 목록(${MANIFEST_PATH})이 없습니다.`);
  let manifest;
  try { manifest = JSON.parse(readFileSync(file, 'utf8')); } catch { fail(`${MANIFEST_PATH}를 읽을 수 없습니다.`); }
  const entries = readEntries(manifest);
  try { git(root, 'cat-file', '-e', `${manifest.verifiedCommit}^{commit}`); } catch {
    fail(`사본 커밋 ${manifest.verifiedCommit.slice(0, 12)}을 이 저장소에서 찾을 수 없습니다.`);
  }
  for (const entry of entries) {
    try { entry.baseline = git(root, 'show', `${manifest.verifiedCommit}:${entry.path}`); } catch {
      fail(`사본 커밋에 ${entry.path}가 없습니다.`);
    }
    if (sha256(entry.baseline) !== entry.hash) fail(`사본 검증 실패: ${entry.path}의 지문이 목록과 다릅니다.`);
  }
  return { manifest, entries };
}

// 파일마다 status('same' | 'changed' | 'missing')와, 되돌릴 때 쓸 내용(restored)을 계산합니다. 읽기만 합니다.
export function comparePolicy({ manifest, entries }, root = defaultRoot) {
  return entries.map((entry) => {
    const target = join(root, entry.path);
    if (!existsSync(target)) return { ...entry, status: 'missing', currentHash: null, restored: entry.baseline };
    const current = readFileSync(target);
    const currentHash = sha256(current);
    if (entry.policyKeys) {
      let currentJson = null;
      try { currentJson = JSON.parse(current.toString('utf8')); } catch { currentJson = null; }
      const baselineJson = JSON.parse(entry.baseline.toString('utf8'));
      if (currentJson && subsetOf(currentJson, entry.policyKeys) === subsetOf(baselineJson, entry.policyKeys)) {
        return { ...entry, status: 'same', currentHash, restored: null };
      }
      // 정책 항목만 사본 값으로 바꾸고, 단계·주소 같은 다른 설정은 지금 값을 그대로 둡니다.
      const merged = { ...(currentJson ?? baselineJson) };
      for (const key of entry.policyKeys) merged[key] = baselineJson[key];
      const changedKeys = entry.policyKeys.filter((key) => canonical(currentJson?.[key]) !== canonical(baselineJson[key]));
      return { ...entry, status: 'changed', currentHash, changedKeys,
        restored: Buffer.from(`${JSON.stringify(merged, null, 2)}\n`, 'utf8') };
    }
    // Windows의 줄 끝(CRLF) 변환만 다른 파일은 같은 것으로 봅니다.
    if (currentHash === entry.hash || sha256(toLf(current)) === entry.hash) {
      return { ...entry, status: 'same', currentHash, restored: null };
    }
    return { ...entry, status: 'changed', currentHash, restored: entry.baseline };
  });
}

// 바뀔 항목 묶음의 확인 번호입니다. 미리보기 뒤에 파일이 또 바뀌면 번호가 달라져 적용이 중단됩니다.
export function changeSetId(manifest, results) {
  const parts = results.filter((item) => item.status !== 'same').map((item) => [item.path, item.currentHash]);
  return sha256(JSON.stringify([manifest.verifiedCommit, parts])).slice(0, 12);
}

function lineChange(root, commit, path) {
  try {
    const [added = '?', removed = '?'] = git(root, 'diff', '--numstat', commit, '--', path).toString().trim().split(/\s+/u);
    return `+${added} / -${removed}줄`;
  } catch {
    return '줄 수를 셀 수 없음';
  }
}

// 실행 전에 보여 주는 계획입니다: 복원할 버전, 사본 검증 결과, 파일별 변경 범위.
export function formatPlan({ manifest, entries }, results, root = defaultRoot) {
  const lines = [
    `복원할 버전: ${manifest.label ?? '검증된 사본'} · 커밋 ${manifest.verifiedCommit.slice(0, 12)} · ${manifest.verifiedAt ?? '시각 미기록'}`,
    `사본 검증: 통과 (${entries.length}개 파일 지문 일치)`, '', '변경 범위:',
  ];
  for (const item of results) {
    if (item.status === 'same') lines.push(`  같음    ${item.path}`);
    else if (item.status === 'missing') lines.push(`  삭제됨  ${item.path}`);
    else if (item.policyKeys) lines.push(`  변경됨  ${item.path} (정책 항목: ${item.changedKeys.join(', ')})`);
    else lines.push(`  변경됨  ${item.path} (${lineChange(root, manifest.verifiedCommit, item.path)})`);
  }
  const changed = results.filter((item) => item.status !== 'same');
  lines.push('', `요약: ${changed.length ? `${changed.length}개 파일이 사본과 다릅니다.` : '사본과 차이가 없습니다.'}`);
  return { lines, changed };
}

// 사본 목록을 만듭니다(통과한 저장점 커밋에서 꺼낸 파일의 지문을 적습니다). 이미 만들어진 목록은 덮어쓰지 않습니다.
export function buildManifest({ root = defaultRoot, commit, files, label, force = false }) {
  const target = join(root, MANIFEST_PATH);
  if (existsSync(target) && !force) fail(`${MANIFEST_PATH}가 이미 있습니다. 검증된 사본은 덮어쓰지 않습니다.`);
  let full;
  try { full = git(root, 'rev-parse', '--verify', `${commit}^{commit}`).toString().trim(); } catch { fail(`커밋 ${commit}을 찾을 수 없습니다.`); }
  if (!COMMIT.test(full)) fail('커밋 번호를 확인할 수 없습니다.');
  const listed = {};
  for (const file of files) {
    let blob;
    try { blob = git(root, 'show', `${full}:${file.path}`); } catch { fail(`커밋 ${full.slice(0, 12)}에 ${file.path}가 없습니다.`); }
    listed[file.path] = file.policyKeys ? { sha256: sha256(blob), policyKeys: file.policyKeys } : sha256(blob);
  }
  let verifiedAt = null;
  try { verifiedAt = git(root, 'show', '-s', '--format=%cI', full).toString().trim() || null; } catch { verifiedAt = null; }
  const manifest = { schema: SCHEMA, label: label ?? '검증된 정책 사본', verifiedCommit: full, verifiedAt, files: listed };
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

// 적용: 사본 목록을 처음부터 다시 읽어 검증하고, 지금 상태를 다시 비교해, 확인 번호가 맞을 때만 사본으로 되돌립니다.
// 되돌린 뒤에도 다시 읽어 사본과 같은지 확인하고, 기록은 그 뒤에 감사 로그 끝에 덧붙이기만 합니다.
export function applyRestore({ root = defaultRoot, confirm, now = new Date() }) {
  const policy = loadVerifiedPolicy(root);
  const results = comparePolicy(policy, root);
  const changed = results.filter((item) => item.status !== 'same');
  if (!changed.length) return { wrote: false, lines: ['되돌릴 항목이 없습니다. 아무것도 바꾸지 않았습니다.'] };
  const id = changeSetId(policy.manifest, results);
  if (confirm !== id) fail(`확인 번호가 맞지 않습니다(현재 ${id}). 미리보기를 다시 보고 실행해 주세요. 아무것도 바꾸지 않았습니다.`);

  for (const item of changed) {
    const target = join(root, item.path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, item.restored);
  }
  const verified = comparePolicy(loadVerifiedPolicy(root), root);
  if (verified.some((item) => item.status !== 'same')) {
    fail('되돌린 뒤에도 사본과 다른 파일이 남았습니다. git diff로 확인해 주세요.');
  }
  mkdirSync(dirname(join(root, AUDIT_PATH)), { recursive: true });
  appendFileSync(join(root, AUDIT_PATH), `${JSON.stringify({
    at: now.toISOString(), action: 'policy_restore', changeSet: id, verifiedCommit: policy.manifest.verifiedCommit,
    files: changed.map((item) => ({ path: item.path, status: item.status, before: item.currentHash,
      after: sha256(item.restored), keys: item.changedKeys ?? null })),
  })}\n`, 'utf8');
  return {
    wrote: true,
    lines: [`${changed.length}개 파일을 사본으로 되돌렸고 ${AUDIT_PATH}에 기록을 덧붙였습니다.`,
      '다음으로 npm run policy:diff 와 1~9단계 시험을 다시 실행해 확인합니다.'],
  };
}
