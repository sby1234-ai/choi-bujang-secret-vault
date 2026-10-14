// 탈환 작전실 화면 스크립트입니다. 서버 GET /api/ops 의 응답만 그리고, 성공 문구를 직접 만들지 않습니다.
// 로그인 토큰·기기 증표는 HttpOnly 쿠키로만 함께 가며, 이 스크립트는 읽지 않고 브라우저 저장소도 쓰지 않습니다.
// 화면의 수치는 응답에 들어 있는 가린 기록을 다시 세어 서버 요약과 맞는지 함께 표시합니다.
const stateBox = document.querySelector('#ops-state');
const area = document.querySelector('#ops');
const STATUS_TEXT = { executed: '실제 실행·조회', not_run: '미실행', error: '조회 실패' };
const RESULT_TEXT = {
  restored: '복원함', unchanged: '이미 같음', backup_not_found: '사본 없음', backup_verification_failed: '사본 검증 실패',
  note_owner_mismatch: '소유자 불일치', restore_failed: '쓰기 실패', restore_verification_failed: '쓴 뒤 검증 실패',
  restore_unavailable: '복원 불가', unknown: '알 수 없음',
};
const DEVICE_TEXT = { pending: '승인 대기', approved: '승인됨', revoked: '회수됨', unknown: '알 수 없음' };

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
function tag(status) { return el('span', STATUS_TEXT[status] ?? '알 수 없음', `tag ${STATUS_TEXT[status] ? status : 'error'}`); }
function line(status, text) { const p = el('p'); p.append(tag(status), document.createTextNode(text)); return p; }
function check(ok, text) { return el('p', `${ok ? '✓ 서버 기록과 일치' : '✗ 서버 기록과 불일치'} · ${text}`, `check ${ok ? 'ok' : 'bad'}`); }
function table(headers, rows) {
  const t = el('table');
  const head = el('tr');
  for (const h of headers) head.append(el('th', h));
  t.append(head);
  for (const row of rows) {
    const tr = el('tr');
    for (const cell of row) tr.append(el('td', cell ?? '—'));
    t.append(tr);
  }
  return t;
}
const reset = (id, title) => { const s = document.querySelector(id); s.replaceChildren(el('h2', title)); return s; };
const count = (list, key, value) => list.filter((item) => item[key] === value).length;

function practice(sec, title, block, note, noun = '가상 요청') {
  sec.append(el('h3', title));
  if (block?.status !== 'executed' || !block.practice) { sec.append(line(block?.status ?? 'error', ' 연습을 실행하지 못했습니다.')); return; }
  const { total, passed, results } = block.practice;
  sec.append(line('executed', ` 배포 서버가 이번 요청에서 ${noun} ${total}건을 실행했고 ${passed}건이 기대대로 나왔습니다. ${note}`));
  sec.append(table(['가상 요청', '결과'], results.map((r) => [r.name, r.passed ? '기대대로' : '기대와 다름'])));
  sec.append(check(results.length === total && count(results, 'passed', true) === passed, `연습 ${results.length}건을 다시 셈`));
}

function render(data) {
  const d = reset('#sec-decider', '판정기 규칙');
  if (Array.isArray(data.decider?.ruleIds)) {
    d.append(line('executed', ` 배포된 판정기의 규칙 ${data.decider.ruleIds.length}개`));
    const ul = el('ul'); for (const id of data.decider.ruleIds) ul.append(el('li', id)); d.append(ul);
  }
  practice(d, '가상 요청 연습', data.decider, '실제 접속 판정이 아닙니다.');
  d.append(el('h3', '실제 접속 판정'), line(data.decider?.live?.status ?? 'not_run', ` ${data.decider?.live?.reason ?? ''}`));

  const t = reset('#sec-detection', '탐지 사건');
  t.append(el('h3', '실제 접속 사건'), line(data.detection?.live?.status ?? 'not_run', ` ${data.detection?.live?.reason ?? ''}`));
  practice(t, '가상 사건 연습(폭주 조회 120건 초과 시 회수 제안)', data.detection, '실제 사건이나 실제 회수가 아닙니다.', '가상 사건');

  const r = reset('#sec-revocation', '회수 상태');
  const dev = data.revocation?.devices;
  r.append(el('h3', '내 기기 승인·회수 기록(devices 표)'));
  if (dev?.status === 'executed') {
    const s = dev.summary;
    r.append(line('executed', ` 기기 ${s.total}대 · 승인됨 ${s.approved} · 승인 대기 ${s.pending} · 회수됨 ${s.revoked}${s.unknown ? ` · 알 수 없음 ${s.unknown}` : ''}`));
    r.append(table(['확인 코드(가림)', '상태', '요청 시각', '승인 시각'], dev.records.map((x) => [x.code, DEVICE_TEXT[x.status] ?? x.status, x.requestedAt, x.approvedAt])));
    const recount = ['pending', 'approved', 'revoked', 'unknown'].every((k) => count(dev.records, 'status', k) === s[k]);
    r.append(check(dev.records.length === s.total && recount, `가린 기록 ${dev.records.length}줄을 상태별로 다시 셈`));
  } else r.append(line(dev?.status ?? 'error', ' 기기 기록을 읽지 못했습니다.'));
  r.append(el('h3', '탐지에 따른 회수 집행'), line(data.revocation?.proposals?.status ?? 'not_run', ` ${data.revocation?.proposals?.reason ?? ''}`));

  const c = reset('#sec-recovery', '복구 버전');
  const p = data.recovery?.policy;
  c.append(el('h3', '정책 사본(policy/verified-policy.json)'));
  if (p?.status === 'executed' && p.commit) {
    c.append(line('executed', ` ${p.label ?? '이름 없음'} · 커밋 ${p.commit} · ${p.verifiedAt ?? '시각 없음'} · 파일 ${p.fileCount}개`));
    c.append(check(Array.isArray(p.files) && p.files.length === p.fileCount, `파일 이름 ${Array.isArray(p.files) ? p.files.length : 0}개를 다시 셈`));
  } else c.append(line('error', ' 정책 사본 정보를 읽지 못했습니다.'));
  c.append(line(data.recovery?.policyDiff?.status ?? 'not_run', ` ${data.recovery?.policyDiff?.reason ?? ''}`));
  const a = data.recovery?.restoreAudit;
  c.append(el('h3', '내 메모 복원 기록(notes_restore_audit 표)'));
  if (a?.status === 'executed') {
    const parts = Object.entries(a.summary.byResult).map(([k, v]) => `${RESULT_TEXT[k] ?? k} ${v}`).join(' · ');
    c.append(line('executed', ` 복원 시도 ${a.summary.total}건${parts ? ` (${parts})` : ''}${a.truncated ? ` · 최근 ${a.summary.shown}건만 표시` : ''}`));
    c.append(table(['시각', '메모 번호(가림)', '결과', '복원 전 해시', '복원 뒤 해시'], a.records.map((x) => [x.at, x.note, RESULT_TEXT[x.result] ?? x.result, x.before, x.after])));
    const recount = Object.entries(a.summary.byResult).every(([k, v]) => count(a.records, 'result', k) === v)
      && Object.values(a.summary.byResult).reduce((n, v) => n + v, 0) === a.records.length;
    c.append(check(a.records.length === a.summary.shown && recount && (a.truncated || a.summary.total === a.records.length), `가린 기록 ${a.records.length}줄을 결과별로 다시 셈`));
  } else c.append(line(a?.status ?? 'error', ' 복원 기록을 읽지 못했습니다.'));

  document.querySelector('#ops-time').textContent = `서버가 요약을 만든 시각 ${data.generatedAt} · 메모 제목·본문은 서버가 읽지도 돌려주지도 않습니다.`;
  area.hidden = false;
}

async function load() {
  stateBox.hidden = false;
  stateBox.textContent = '서버에 요약을 요청하는 중입니다.';
  area.hidden = true;
  const get = () => fetch('/api/ops', { credentials: 'same-origin', cache: 'no-store' });
  try {
    let response = await get();
    if (response.status === 401) {
      const refreshed = await fetch('/api/refresh', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (refreshed.ok) response = await get();
    }
    if (response.status === 401) { stateBox.textContent = '로그인이 필요합니다. 내 자료실에서 로그인한 뒤 다시 열어 주세요.'; return; }
    if (response.status === 403) { stateBox.textContent = '승인된 기기에서만 작전실을 볼 수 있습니다. 내 자료실에서 기기 승인을 먼저 받아 주세요.'; return; }
    if (!response.ok) { stateBox.textContent = `서버가 요약을 돌려주지 못했습니다 (HTTP ${response.status}).`; return; }
    render(await response.json());
    stateBox.hidden = true;
  } catch {
    stateBox.textContent = '서버에 연결하지 못했습니다.';
  }
}

document.querySelector('#reload').addEventListener('click', load);
load();
