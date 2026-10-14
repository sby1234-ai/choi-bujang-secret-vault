// 12단계 탈환 작전실이 쓰는 요약·가리기 함수입니다(DB 없이 시험할 수 있게 순수 함수로 둡니다).
// 서버 기록은 그대로 내보내지 않고 가린 모양(메모 번호 앞뒤 4자리, 해시 앞 8자리, 확인 코드 일부)으로만 돌려줍니다.
// 메모 제목·본문은 읽지도 돌려주지도 않습니다. 수치(summary)는 반드시 같은 기록(records)에서 셉니다.

export const AUDIT_RESULTS = Object.freeze([
  'restored', 'unchanged', 'backup_not_found', 'backup_verification_failed', 'note_owner_mismatch',
  'restore_failed', 'restore_verification_failed', 'restore_unavailable',
]);
export const DEVICE_STATUSES = Object.freeze(['pending', 'approved', 'revoked']);

export function maskId(value) {
  return typeof value === 'string' && value.length >= 12 ? `${value.slice(0, 4)}…${value.slice(-4)}` : '가림';
}
export function maskHash(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value) ? `${value.slice(0, 8)}…` : null;
}
export function maskCode(value) {
  return typeof value === 'string' && /^[0-9A-F]{4}-[0-9A-F]{4}$/u.test(value)
    ? `${value.slice(0, 2)}**-**${value.slice(-2)}` : '가림';
}
const iso = (value) => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null);

// 기기 기록: 상태별 개수와 가린 기록. 알 수 없는 상태는 'unknown'으로 세어 숨기지 않습니다.
export function summarizeDevices(rows) {
  const records = (Array.isArray(rows) ? rows : []).map((row) => ({
    code: maskCode(row?.code),
    status: DEVICE_STATUSES.includes(row?.status) ? row.status : 'unknown',
    requestedAt: iso(row?.requested_at),
    approvedAt: iso(row?.approved_at),
  }));
  const summary = { total: records.length, pending: 0, approved: 0, revoked: 0, unknown: 0 };
  for (const record of records) summary[record.status] += 1;
  return { summary, records };
}

// 복원 감사 기록: 결과별 개수와 가린 기록. totalInDb는 DB가 센 전체 줄 수(기록을 일부만 받으면 truncated: true).
export function summarizeAudit(rows, totalInDb) {
  const records = (Array.isArray(rows) ? rows : []).map((row) => ({
    at: iso(row?.at),
    note: maskId(row?.note_id),
    result: AUDIT_RESULTS.includes(row?.result) ? row.result : 'unknown',
    before: maskHash(row?.before_sha256),
    after: maskHash(row?.after_sha256),
  }));
  const byResult = {};
  for (const record of records) byResult[record.result] = (byResult[record.result] ?? 0) + 1;
  const total = Number.isInteger(totalInDb) ? totalInDb : records.length;
  return { summary: { total, shown: records.length, byResult }, records, truncated: total !== records.length };
}

// 정책 사본(복구 버전): 커밋은 앞 12자리만, 파일은 이름만 셉니다.
export function policyVersion(manifest) {
  const files = manifest && typeof manifest.files === 'object' && manifest.files ? Object.keys(manifest.files) : [];
  const commit = typeof manifest?.verifiedCommit === 'string' && /^[0-9a-f]{40}$/u.test(manifest.verifiedCommit)
    ? manifest.verifiedCommit.slice(0, 12) : null;
  return { label: typeof manifest?.label === 'string' ? manifest.label : null, commit, verifiedAt: iso(manifest?.verifiedAt), fileCount: files.length, files };
}

// 연습 결과 묶음: 이름과 통과 여부만 두고 개수를 같은 목록에서 셉니다.
export function practiceSummary(results) {
  const list = (Array.isArray(results) ? results : []).map((item) => ({ name: String(item?.name ?? ''), passed: item?.passed === true }));
  return { total: list.length, passed: list.filter((item) => item.passed).length, results: list };
}
