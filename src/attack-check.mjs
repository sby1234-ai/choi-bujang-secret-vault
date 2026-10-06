// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { readFile } from 'node:fs/promises';

function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

async function readJson(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) });
  let data = null;
  if (response.ok) {
    try {
      data = await response.json();
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return { status: response.status, data };
}

// 응답 본문은 읽지 않고 상태 코드만 기록합니다.
async function status(app, method, path, { headers = {}, body } = {}) {
  const response = await fetch(new URL(path, app), {
    method, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return response.status;
}

const ABSENT_ID = '00000000-0000-4000-8000-000000000000';

export async function runAttackChecks(config) {
  if (!Number.isInteger(config.step) || config.step < 1 || config.step > 5) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
    const { status: code, data } = await readJson(new URL('/data.json', app));
    const visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
      && data.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${code})` }];
  }

  if (config.step === 2) {
    const file = await readJson(new URL('/data.json', app));
    const fileNotes = Array.isArray(file.data?.notes) ? file.data.notes.length : 0;
    const api = await readJson(new URL('/api/notes', app));
    const apiNotes = Array.isArray(api.data?.notes) ? api.data.notes.length : 0;
    return [
      { attackId: 'public_data_json_read', expected: '/data.json에서 메모가 보이지 않음',
        observed: fileNotes === 0 ? `/data.json에서 메모 0건 (HTTP ${file.status})` : `/data.json에서 메모 ${fileNotes}건이 보임` },
      { attackId: 'anonymous_api_read', expected: '3단계 전이라 비로그인 요청으로 서버 API 호출이 가능함(남은 약점)',
        observed: apiNotes > 0 ? `비로그인 요청에서 /api/notes 메모 ${apiNotes}건이 보임 (HTTP ${api.status})` : `비로그인 요청에서 /api/notes 메모가 보이지 않음 (HTTP ${api.status})` },
    ];
  }

  // 3·4단계: 로그인 없는 요청과 가짜 토큰은 모두 거부되어야 합니다.
  const fakeToken = { Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' };
  const checks = [
    ['anonymous_list_read', '로그인 없는 목록 조회가 거부됨(401)', 'GET', '/api/notes', {}],
    ['anonymous_note_create', '로그인 없는 메모 추가가 거부됨(401)', 'POST', '/api/notes', { body: {} }],
    ['anonymous_note_read', '로그인 없는 한 건 조회가 거부됨(401)', 'GET', `/api/notes/${ABSENT_ID}`, {}],
    ['anonymous_note_update', '로그인 없는 메모 수정이 거부됨(401)', 'PUT', `/api/notes/${ABSENT_ID}`, { body: {} }],
    ['anonymous_note_delete', '로그인 없는 메모 삭제가 거부됨(401)', 'DELETE', `/api/notes/${ABSENT_ID}`, {}],
    ['forged_token_read', '가짜 토큰을 붙인 목록 조회가 거부됨(401)', 'GET', '/api/notes', { headers: fakeToken }],
  ];
  const results = [];
  for (const [attackId, expected, method, path, options] of checks) {
    const code = await status(app, method, path, options);
    results.push({ attackId, expected, observed: code === 401 ? `요청이 거부됨 (HTTP ${code})` : `거부되지 않음 (HTTP ${code})` });
  }
  if (config.step === 3) {
    results.push({ attackId: 'normal_a_login_crud', expected: 'A 로그인 뒤 메모 추가·수정·삭제가 됨',
      observed: '미실행 (A 계정 비밀번호가 필요해 자동 점검에서는 보내지 않았고 화면에서 직접 확인함)' });
    return results;
  }

  // 4·5단계: 학습 DB의 Data API(원본 자료 경로)를 공개용(publishable) 키로 직접 부르면 거부되어야 합니다. 키는 화면 코드에 이미 있는 공개 값입니다.
  const page = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const publishableKey = /sb_publishable_[A-Za-z0-9_-]+/u.exec(page)?.[0];
  if (!publishableKey) throw new Error('public/index.html에서 공개용(publishable) 키를 찾지 못했습니다.');
  const dataApi = typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
    ? config.originalApiUrl
    : new URL('/rest/v1/notes', new URL(config.identityProvider.issuer).origin).href;
  const anonHeaders = { apikey: publishableKey };
  const direct = [
    ['anon_data_api_read', '공개용 키로 DB 메모 직접 조회가 거부됨(401·403)', 'GET', `${dataApi}?select=id&limit=1`],
    ['anon_data_api_delete', '공개용 키로 DB 메모 직접 삭제가 거부됨(401·403)', 'DELETE', `${dataApi}?id=eq.${ABSENT_ID}`],
  ];
  for (const [attackId, expected, method, url] of direct) {
    const code = await status(app, method, url, { headers: anonHeaders });
    results.push({ attackId, expected, observed: code === 401 || code === 403 ? `요청이 거부됨 (HTTP ${code})` : `거부되지 않음 (HTTP ${code})` });
  }
  results.push({ attackId: 'a_b_own_note_crud', expected: 'A·B가 각자 자기 메모를 추가·수정·삭제할 수 있음',
    observed: '미실행 (계정 비밀번호가 필요해 자동 점검에서는 보내지 않았고 화면에서 직접 확인함)' });
  results.push({ attackId: 'cross_account_note_access', expected: 'B가 A 메모의 번호로 읽기·수정·삭제하면 거부되고, 본문 owner_id를 바꿔 추가해도 거부됨',
    observed: '미실행 (B 로그인 토큰이 필요해 자동 점검에서는 보내지 않았고 브라우저 콘솔에서 직접 확인함)' });
  return results;
}
