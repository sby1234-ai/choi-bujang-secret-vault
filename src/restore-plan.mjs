// 10단계: 침해 전에 검증한 안전 정책 사본과 현재 시험 정책의 차이만 보여 줍니다.
// 이 파일은 읽기만 합니다. 실제 운영 정책(src/decider.mjs, aleph.config.json)과 자료는 바꾸지 않습니다.
// 사본이 없거나 검증에 실패하면 차이를 보여 주지 않고 중단합니다.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SNAPSHOT_SCHEMA = 'vault.policy.snapshot.v1';
export const SNAPSHOT_PATH = join('backup', 'policy-snapshot.json');

const RULE_NAME = /^[a-z][a-z0-9_.-]{0,79}$/iu;
const ROUTE_NAME = /^(?:GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9_\-/.:]{0,120}$/u;
const SECRET_LIKE = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{8,}|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ/iu;
const SNAPSHOT_KEYS = ['schema', 'version', 'sourceCommit', 'policy', 'sha256'];
const POLICY_KEYS = ['ruleIds', 'allowedRoutes'];

const fail = (message) => { throw new Error(message); };
const sameKeys = (object, keys) => Object.keys(object).sort().join(',') === [...keys].sort().join(',');
const isPlain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// 순서가 달라도 같은 정책이면 같은 값이 되도록 정렬해서 만듭니다.
export function canonicalPolicy(policy) {
  return {
    ruleIds: [...new Set(policy.ruleIds)].sort(),
    allowedRoutes: [...new Set(policy.allowedRoutes)].sort(),
  };
}

export function hashPolicy(policy) {
  return createHash('sha256').update(JSON.stringify(canonicalPolicy(policy))).digest('hex');
}

function checkList(name, list, pattern, max) {
  if (!Array.isArray(list) || list.length === 0 || list.length > max
      || list.some(item => typeof item !== 'string' || !pattern.test(item))
      || new Set(list).size !== list.length) {
    fail(`정책 사본의 ${name} 모양이 올바르지 않습니다.`);
  }
}

// 사본의 모양, 알 수 없는 항목, 비밀값처럼 보이는 문자열, 해시 일치를 모두 확인합니다.
export function verifySnapshot(snapshot) {
  if (!isPlain(snapshot) || !sameKeys(snapshot, SNAPSHOT_KEYS)) fail('정책 사본의 항목이 계약과 다릅니다.');
  if (snapshot.schema !== SNAPSHOT_SCHEMA) fail('정책 사본의 schema가 맞지 않습니다.');
  if (typeof snapshot.version !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/u.test(snapshot.version)) {
    fail('정책 사본의 version 모양이 올바르지 않습니다.');
  }
  if (typeof snapshot.sourceCommit !== 'string' || !/^[0-9a-f]{7,40}$/u.test(snapshot.sourceCommit)) {
    fail('정책 사본의 sourceCommit 모양이 올바르지 않습니다.');
  }
  if (!isPlain(snapshot.policy) || !sameKeys(snapshot.policy, POLICY_KEYS)) fail('정책 사본의 policy 항목이 계약과 다릅니다.');
  checkList('ruleIds', snapshot.policy.ruleIds, RULE_NAME, 80);
  checkList('allowedRoutes', snapshot.policy.allowedRoutes, ROUTE_NAME, 20);
  if (SECRET_LIKE.test(JSON.stringify(snapshot))) fail('정책 사본에 비밀값처럼 보이는 내용이 있습니다.');
  if (typeof snapshot.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(snapshot.sha256)) {
    fail('정책 사본의 sha256 모양이 올바르지 않습니다.');
  }
  if (hashPolicy(snapshot.policy) !== snapshot.sha256) fail('정책 사본의 해시가 내용과 맞지 않습니다. 사본이 바뀐 것으로 봅니다.');
  return snapshot;
}

export function readSnapshot(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    fail('검증된 정책 사본이 없습니다.');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('정책 사본을 JSON으로 읽을 수 없습니다.');
  }
  return verifySnapshot(parsed);
}

// 지금 시험 정책: 판정기의 규칙 이름과 설정의 허용 경로입니다. 읽기만 합니다.
export async function loadCurrentPolicy(root) {
  const { RULE_IDS } = await import(pathToFileURL(join(root, 'src', 'decider.mjs')).href);
  const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
  if (!Array.isArray(RULE_IDS) || !Array.isArray(config.allowedRoutes)) fail('현재 정책을 읽을 수 없습니다.');
  return canonicalPolicy({ ruleIds: [...RULE_IDS], allowedRoutes: [...config.allowedRoutes] });
}

const onlyIn = (a, b) => a.filter(item => !b.includes(item));

// 복원하면 현재 정책이 사본과 같아진다고 보고, 무엇이 되살아나고 무엇이 사라지는지 셉니다.
export function diffPolicy(snapshotPolicy, currentPolicy) {
  const saved = canonicalPolicy(snapshotPolicy);
  const now = canonicalPolicy(currentPolicy);
  const part = (a, b) => ({ restored: onlyIn(a, b), removed: onlyIn(b, a) });
  const ruleIds = part(saved.ruleIds, now.ruleIds);
  const allowedRoutes = part(saved.allowedRoutes, now.allowedRoutes);
  const count = ruleIds.restored.length + ruleIds.removed.length
    + allowedRoutes.restored.length + allowedRoutes.removed.length;
  return { ruleIds, allowedRoutes, changed: count > 0, count };
}

export function formatPlan(snapshot, diff) {
  const lines = [
    '복원 계획 (미리보기 · 아무것도 바꾸지 않았습니다)',
    `복원할 버전: ${snapshot.version} · 원본 커밋 ${snapshot.sourceCommit} · 해시 ${snapshot.sha256.slice(0, 12)} 검증됨`,
    `변경 범위: ${diff.changed ? `${diff.count}건` : '없음 (현재 정책이 사본과 같습니다)'}`,
  ];
  const sections = [['규칙', diff.ruleIds], ['허용 경로', diff.allowedRoutes]];
  for (const [label, part] of sections) {
    for (const item of part.restored) lines.push(`  + ${label} 되살림: ${item}`);
    for (const item of part.removed) lines.push(`  - ${label} 제거: ${item}`);
  }
  lines.push('이 명령은 읽기 전용이며 실제 운영 정책과 자료실 자료를 바꾸지 않습니다.');
  return lines.join('\n');
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const root = resolve(import.meta.dirname, '..');
    const snapshot = readSnapshot(join(root, SNAPSHOT_PATH));
    const current = await loadCurrentPolicy(root);
    process.stdout.write(`${formatPlan(snapshot, diffPolicy(snapshot.policy, current))}\n`);
  } catch (error) {
    process.stderr.write(`복원 중단: ${error.message}\n`);
    process.exitCode = 1;
  }
}
