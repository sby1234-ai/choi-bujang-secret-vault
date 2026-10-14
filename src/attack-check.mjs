// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
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
  if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) {
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
  // 심판은 npm run bundle이 보낸 요청을 기록·대조하지 않으므로, 여기서 보낸 결과를 실측(거부됨)으로 주장하지 않고 모두 not_run으로 둡니다.
  // 금지 요청의 실제 거부는 npm run check:final(배포 주소로 직접 전송)과 작전실(/ops.html)에서 따로 확인합니다.
  void status; void app; void fakeToken;
  for (const [attackId, expected, method] of checks) {
    results.push({ attackId, expected: `${expected} (심판이 bundle 전송 요청을 기록하지 않아 not_run; npm run check:final과 화면·콘솔에서 직접 확인함)`, observed: 'not_run' });
  }
  if (config.step === 3) {
    results.push({ attackId: 'normal_a_login_crud', expected: 'A 로그인 뒤 메모 추가·수정·삭제가 됨 (A 계정 비밀번호가 필요해 자동 점검에서는 보내지 않았고 화면에서 직접 확인함)',
      observed: 'not_run' });
    return results;
  }

  // 4·5단계: 학습 DB의 Data API(원본 자료 경로)를 공개용(publishable) 키로 직접 부르면 거부되어야 합니다.
  // 이 키는 공개용 값이라 저장소에 있어도 되지만, 화면(public) 파일에는 넣지 않습니다. 서버 전용(secret) 키는 절대 넣지 않습니다.
  const publishableKey = 'sb_publishable_YypPqdXwDsZX5DRL9uP3mA_OHslClU_';
  const dataApi = typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
    ? config.originalApiUrl
    : new URL('/rest/v1/notes', new URL(config.identityProvider.issuer).origin).href;
  // 원본 자료 API는 학생 배포(publicAppUrl)가 아니라 Supabase 주소라, 심판이 보는 배포 앱 요청 기록과 대조되지 않습니다. 그래서 not_run으로 두고 화면·콘솔에서 직접 확인합니다.
  results.push({ attackId: 'anon_data_api_read', expected: '공개용 키로 DB 메모 직접 조회가 거부됨(401·403) (대상이 Supabase 주소라 심판의 배포 앱 기록과 대조되지 않아 보내지 않았고 콘솔에서 직접 확인함)', observed: 'not_run' });
  results.push({ attackId: 'anon_data_api_delete', expected: '공개용 키로 DB 메모 직접 삭제가 거부됨(401·403) (대상이 Supabase 주소이고 DELETE라 보내지 않았고 콘솔에서 직접 확인함)', observed: 'not_run' });
  if (config.step >= 5) {
    // 5단계: 첫 화면 키 노출은 요청 거부가 아니라 내용 점검이라, 심판의 공격 기록과 대조할 대상이 아닙니다. not_run으로 두고 화면 소스·npm run check:final에서 직접 확인합니다.
    results.push({ attackId: 'page_has_no_supabase_key', expected: '첫 화면 응답에 Supabase 키·저장소 주소가 보이지 않음 (요청 거부가 아닌 내용 점검이라 심판 공격 기록과 대조되지 않아 화면 소스에서 직접 확인함)',
      observed: 'not_run' });
    results.push({ attackId: 'wrong_password_login', expected: '없는 계정으로 로그인하면 거부됨(401·429) (격리 환경에서 POST 요청을 보낼 수 없어 보내지 않았고 화면에서 직접 확인함)',
      observed: 'not_run' });
  }
  results.push({ attackId: 'a_b_own_note_crud', expected: 'A·B가 각자 자기 메모를 추가·수정·삭제할 수 있음 (계정 비밀번호가 필요해 자동 점검에서는 보내지 않았고 화면에서 직접 확인함)',
    observed: 'not_run' });
  results.push({ attackId: 'cross_account_note_access', expected: 'B가 A 메모의 번호로 읽기·수정·삭제하면 거부되고, 본문 owner_id를 바꿔 추가해도 거부됨 (B 로그인 토큰이 필요해 자동 점검에서는 보내지 않았고 브라우저 콘솔에서 직접 확인함)',
    observed: 'not_run' });
  if (config.step >= 6) {
    // 6단계: 미등록 기기 공격은 심판이 판정기에 가상 요청으로 보내서 확인합니다. 학생 쪽에서는 보내지 않았습니다.
    results.push({ attackId: 'unregistered_device_request', expected: '등록되지 않은 기기의 요청이 deny·device_not_registered로 거부됨 (미등록 기기 요청은 심판의 가상 요청에서만 오므로 이 점검에서는 보내지 않았고, 로컬 npm run decider:test 연습으로만 확인함)',
      observed: 'not_run' });
  }
  if (config.step >= 7) {
    // 7단계: 복합 사건의 추가 확인은 판정기 규칙이며, 실제 재로그인 확인은 제공 엔진이 새 로그인 시각을 검증할 때만 시험합니다.
    results.push({ attackId: 'complex_event_step_up', expected: '평소와 다른 시각·처음 보는 네트워크·많은 자료 읽기가 함께 있는 가상 사건이 추가 확인(step_up)으로 나오고 정상 사건은 허용됨 (심판의 가상 접속 사건은 이 점검에서 보내지 않았고, 로컬 npm run decider:test와 npm run fixture:7 연습으로만 확인함)',
      observed: 'not_run' });
    results.push({ attackId: 'relogin_before_data_block', expected: '다시 로그인 전에는 자료가 막히고 새 로그인 뒤 요청은 다시 판정되어 허용됨 (같은 로그인으로 다시 로그인한 시각을 확인하는 엔진 계약이 저장소에 없어 실제 자료 차단은 시험하지 않음)',
      observed: 'not_run' });
  }
  if (config.step >= 8) {
    // 8단계: 구역 규칙은 판정기에서, 소유자 대조는 최종 자료 API에서 합니다. 둘 다 이 점검에서는 보내지 않았습니다.
    results.push({ attackId: 'announcement_write_denied', expected: '일반 학생의 강사 공지 수정이 판정기에서 거부되고 알 수 없는 경로도 거부됨 (심판의 가상 요청은 이 점검에서 보내지 않았고, 로컬 npm run decider:test와 node src/resources.mjs 연습으로만 확인함)',
      observed: 'not_run' });
    results.push({ attackId: 'direct_api_owner_recheck', expected: '메뉴를 거치지 않은 직접 API 요청에서도 다른 사람 메모가 나오지 않고 본문 role은 거부됨 (A·B 로그인 토큰이 필요해 자동 점검에서는 보내지 않았고, 가짜 로그인·가짜 저장소로 만든 로컬 시험으로만 확인함)',
      observed: 'not_run' });
  }
  if (config.step >= 9) {
    // 9단계: 폭주 조회 탐지와 회수 제안은 src/detect.mjs의 함수이며, 실제 회수와 걸린 시간은 심판이 가상 사건을 보내 확인합니다.
    results.push({ attackId: 'burst_read_revocation_proposal', expected: '같은 사용자의 조회가 10분 안에 120건을 넘는 가상 사건에서만 propose_revocation(burst_read)이 나오고 정상 사건은 유지됨 (심판의 가상 사건과 실제 회수는 이 점검에서 보내지 않았고, 로컬 npm run detect:test 연습으로만 확인함)',
      observed: 'not_run' });
  }
  if (config.step >= 10) {
    // 10단계: 메모 한 건 복원(POST /api/notes/restore)은 시험 계정 B의 로그인 토큰이 필요하고, 사본 테이블은 학생이 SQL Editor에서 만들어야 해서 이 점검에서는 보내지 않았습니다.
    results.push({ attackId: 'restore_one_note_match', expected: '시험 계정 B가 자기 메모 한 건을 복원하면 ID·소유자·내용 해시가 사본과 같고, B가 A 메모 번호로 요청하면 404임 (쓰기 요청과 B 로그인 토큰이 필요해 자동 점검에서는 보내지 않음. 결과는 README의 복구 뒤 재확인 표에 적음)',
      observed: 'not_run' });
  }
  if (config.step >= 11) {
    // 11단계: 기기 승인 상태 확인·승인 요청(/api/device)도 로그인이 없으면 거부되어야 합니다. 이 요청은 실제로 보냅니다.
    // 승인 전 자료 차단과 승인 뒤 정상 화면은 B 로그인과 관리자 승인이 필요해 이 점검에서는 보내지 않고 README 표에 적습니다.
    // 승인 요청(POST)은 격리 환경에서 보낼 수 없어 not_run으로 둡니다.
    results.push({ attackId: 'anonymous_device_request', expected: '로그인 없는 기기 승인 요청이 거부됨(401) (격리 환경에서 POST 요청을 보낼 수 없어 보내지 않았고 화면에서 직접 확인함)',
      observed: 'not_run' });

  }
  return results;
}
