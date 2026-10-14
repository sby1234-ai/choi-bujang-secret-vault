// 12단계 총공세 점검표: 1~11단계의 정상·금지 요청을 배포 주소로 실제로 보내 기대 결과와 실측 결과를 한 표로 남깁니다.
// 로그인 토큰·심판 가상 요청이 필요해 이 스크립트에서 보낼 수 없는 시험은 '미실행'으로만 적고, 임의로 통과 처리하지 않습니다.
// 요청마다 X-Request-Id(이 스크립트가 만든 UUID)를 붙이고 보낸 시각(UTC)을 함께 적습니다. 메모 제목·본문·토큰은 보내지도 적지도 않습니다.
// 사용: node scripts/final-check.mjs        (표를 화면과 artifacts/final-check.md 에 씁니다)
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));

function appUrl() {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.pathname !== '/') throw new Error('aleph.config.json의 실제 배포 주소(https)를 먼저 넣어 주세요.');
  return app;
}
const app = appUrl();
const ABSENT = '00000000-0000-4000-8000-000000000000';
const PUBLISHABLE = 'sb_publishable_YypPqdXwDsZX5DRL9uP3mA_OHslClU_';
const dataApi = typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
  ? config.originalApiUrl : new URL('/rest/v1/notes', new URL(config.identityProvider.issuer).origin).href;

// 한 요청을 보내고 상태 코드만 읽습니다(본문은 읽지 않음). 요청 ID와 보낸 시각을 함께 돌려줍니다.
async function send(method, url, { headers = {}, body } = {}) {
  const requestId = randomUUID();
  const at = new Date().toISOString();
  try {
    const response = await fetch(url, {
      method, redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { 'X-Request-Id': requestId, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { requestId, at, observed: `HTTP ${response.status}`, code: response.status };
  } catch {
    return { requestId, at, observed: '연결 실패', code: null };
  }
}
const FORGED = { Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' };
const ok = (codes, code) => code !== null && codes.includes(code);

// 보낼 수 있는 금지·정상 요청: [단계, 구분, 설명, 기대, 판정 함수, 요청]
const SENDABLE = [
  [3, '금지', '로그인 없는 목록 조회', '401', (c) => c === 401, ['GET', new URL('/api/notes', app)]],
  [3, '금지', '로그인 없는 메모 추가', '401', (c) => c === 401, ['POST', new URL('/api/notes', app), { body: {} }]],
  [3, '금지', '로그인 없는 한 건 조회', '401', (c) => c === 401, ['GET', new URL(`/api/notes/${ABSENT}`, app)]],
  [3, '금지', '로그인 없는 메모 수정', '401', (c) => c === 401, ['PUT', new URL(`/api/notes/${ABSENT}`, app), { body: {} }]],
  [3, '금지', '로그인 없는 메모 삭제', '401', (c) => c === 401, ['DELETE', new URL(`/api/notes/${ABSENT}`, app)]],
  [3, '금지', '가짜 토큰을 붙인 목록 조회', '401', (c) => c === 401, ['GET', new URL('/api/notes', app), { headers: FORGED }]],
  [5, '금지', '공개용 키로 DB 메모 직접 조회', '401·403', (c) => ok([401, 403], c), ['GET', `${dataApi}?select=id&limit=1`, { headers: { apikey: PUBLISHABLE } }]],
  [5, '금지', '공개용 키로 DB 메모 직접 삭제', '401·403', (c) => ok([401, 403], c), ['DELETE', `${dataApi}?id=eq.${ABSENT}`, { headers: { apikey: PUBLISHABLE } }]],
  [5, '금지', '없는 계정으로 로그인', '401·429', (c) => ok([401, 429], c), ['POST', new URL('/api/login', app), { body: { email: 'nobody@invalid.test', password: 'wrong-password-for-check' } }]],
  [10, '금지', '로그인 없는 메모 복원 요청', '401', (c) => c === 401, ['POST', new URL('/api/notes/restore', app), { body: { id: ABSENT } }]],
  [11, '금지', '로그인 없는 기기 승인 요청', '401', (c) => c === 401, ['POST', new URL('/api/device', app), { body: {} }]],
  [11, '금지', '로그인 없는 작전실 요약 요청', '401', (c) => c === 401, ['GET', new URL('/api/ops', app)]],
  [1, '정상', '배포 첫 화면이 열림', '200', (c) => c === 200, ['GET', new URL('/', app)]],
];

// 이 스크립트로는 보낼 수 없어 실측하지 못하는 시험(임의 통과 금지, 미실행으로만 남김).
const NOT_RUN = [
  [1, '금지', '공개 /data.json에 가상 메모가 보이지 않음', '메모 0건', '브라우저에서 /data.json 직접 열어 확인(화면 점검)'],
  [3, '정상', 'A 로그인 뒤 메모 추가·수정·삭제', '됨', 'A 계정 비밀번호가 필요해 자동 점검에서 보내지 않음(화면에서 확인)'],
  [4, '정상', 'A·B가 각자 자기 메모만 보고 추가·수정·삭제', '됨', '계정 비밀번호가 필요해 자동 점검에서 보내지 않음(화면에서 확인)'],
  [4, '금지', 'B가 A 메모 번호로 읽기·수정·삭제', '404', 'B 로그인 토큰이 필요해 자동 점검에서 보내지 않음(B 탭 콘솔에서 확인)'],
  [4, '금지', 'B가 본문 owner_id를 A로 바꿔 추가', '403', 'B 로그인 토큰이 필요(B 탭 콘솔에서 확인)'],
  [5, '금지', '첫 화면 소스에 Supabase 키·주소 없음', '없음', 'npm run bundle의 page_has_no_supabase_key 점검으로 확인'],
  [6, '정상', '등록 기기의 정상 요청', 'allow', '심판 가상 요청이라 자동 점검에서 보내지 않음(npm run decider:test 연습)'],
  [6, '금지', '미등록 기기의 요청', 'deny(device_not_registered)', '심판 가상 요청(npm run decider:test 연습)'],
  [7, '정상', '정상 접속 사건', 'allow', '심판 가상 사건(npm run fixture:7 연습)'],
  [7, '금지', '복합 이상 접속', 'step_up', '심판 가상 사건(npm run fixture:7 연습)'],
  [8, '정상', '내 메모 한 건 읽기·수정', 'allow', '심판 가상 요청(node src/resources.mjs, decider:test 연습)'],
  [8, '금지', '강사 공지 수정·목록·삭제·본문 role', '거부', '심판 가상 요청과 B 로그인 토큰이 필요(연습·콘솔에서 확인)'],
  [9, '정상', '정상 조회와 120건 조회', 'observe', '심판 가상 사건(npm run detect:test 연습)'],
  [9, '금지', '10분 안에 121건 이상 조회', 'propose_revocation(burst_read)', '심판 가상 사건(npm run detect:test 연습)'],
  [10, '정상', 'B가 자기 메모 한 건 복원', '200·사본과 일치', 'B 로그인 토큰과 쓰기가 필요(B 탭 콘솔에서 확인)'],
  [10, '금지', 'B가 A 메모 번호로 복원 요청', '404', 'B 로그인 토큰이 필요(B 탭 콘솔에서 확인)'],
  [11, '정상', '승인된 기기에서 메모 목록·추가·수정·삭제', '됨', 'B 로그인과 기기 승인이 필요(화면에서 확인)'],
  [11, '금지', '승인 전 기기의 보호 자료 요청', '403(DEVICE_NOT_APPROVED)', 'B 로그인 토큰이 필요(B 탭 콘솔에서 확인)'],
];

const esc = (text) => String(text).replaceAll('|', '\\|');

async function main() {
  const rows = [];
  for (const [stage, kind, desc, expected, judge, req] of SENDABLE) {
    const r = await send(...req);
    const verdict = r.code === null ? '연결 실패' : (judge(r.code) ? '일치' : '불일치');
    rows.push({ stage, kind, desc, expected, observed: r.observed, verdict, requestId: r.requestId, at: r.at });
  }
  for (const [stage, kind, desc, expected, reason] of NOT_RUN) {
    rows.push({ stage, kind, desc, expected, observed: '미실행', verdict: '미실행', requestId: '—', at: '—', reason });
  }
  rows.sort((a, b) => a.stage - b.stage || a.kind.localeCompare(b.kind));

  const sent = rows.filter((row) => row.observed !== '미실행');
  const matched = sent.filter((row) => row.verdict === '일치').length;
  const forbiddenSent = sent.filter((row) => row.kind === '금지');
  const forbiddenOk = forbiddenSent.every((row) => row.verdict === '일치');
  const header = ['단계', '구분', '요청', '기대', '실측', '판정', '요청 ID', '보낸 시각(UTC)'];
  const lines = [
    `# 1~11단계 정상·금지 요청 점검표 (${new Date().toISOString()})`,
    '',
    `- 배포 주소: ${app.origin}`,
    `- 실제로 보낸 요청: ${sent.length}건 중 기대와 일치 ${matched}건 (금지 요청 ${forbiddenSent.length}건은 ${forbiddenOk ? '모두 거부됨' : '일부 거부되지 않음'})`,
    `- 미실행: ${rows.length - sent.length}건 (로그인 토큰·심판 가상 요청이 필요해 이 스크립트로는 보내지 않음, 임의 통과 처리하지 않음)`,
    '- 정상 요청(로그인 성공·본인 메모 사용)은 계정 비밀번호가 필요해 대부분 미실행이며 화면·콘솔에서 따로 확인합니다.',
    '',
    `| ${header.join(' | ')} |`,
    `| ${header.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${[row.stage, row.kind, esc(row.desc), esc(row.expected), esc(row.observed), row.verdict, row.requestId, row.at].join(' | ')} |`),
    '',
    '미실행 사유:',
    ...rows.filter((row) => row.reason).map((row) => `- ${row.stage}단계 ${row.kind} · ${esc(row.desc)}: ${esc(row.reason)}`),
    '',
    '이 표는 제가 보낸 요청의 실측 기록이며 심판의 판정이 아닙니다. 메모 제목·본문·토큰은 보내지도 적지도 않았습니다.',
    '',
  ];
  const out = join(root, 'artifacts', 'final-check.md');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, lines.join('\n'), 'utf8');
  for (const row of rows) {
    process.stdout.write(`${row.stage} ${row.kind} ${row.verdict.padEnd(4)} ${row.desc} → ${row.observed}\n`);
  }
  process.stdout.write(`\n점검표: ${out}\n보낸 요청 ${sent.length}건 중 일치 ${matched}건, 금지 ${forbiddenSent.length}건 ${forbiddenOk ? '모두 거부' : '일부 통과(확인 필요)'}, 미실행 ${rows.length - sent.length}건\n`);
  if (forbiddenSent.some((row) => row.verdict !== '일치')) process.exitCode = 1;
}

main().catch((error) => { process.stderr.write(`점검표 생성 중 첫 오류: ${error.message}\n`); process.exitCode = 1; });
