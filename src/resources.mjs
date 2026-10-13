// 자료실의 자원 ID 표입니다. 요청의 동작(method)과 경로(route 또는 path)로 "이 요청이 어느 자원 구역인지"를 알려 줍니다.
// 이 파일은 구역에 이름만 붙이고, 누가 무엇을 해도 되는지는 정하지 않습니다(허용·거부 규칙은 판정기가 따로 가집니다).
// 표에 없는 경로는 추측해서 메모로 채우지 않고 null 을 돌려줍니다.
//
// 자료 하나를 고르는 것은 경로의 마지막 조각(:id) 하나뿐입니다. 쿼리(?...)로 기능을 고르지 않고,
// :id 와 같은 깊이에 export 같은 기능 이름을 두지 않습니다. 그래서 그런 이름이 :id 자리에 오면 자원으로 보지 않습니다.
//
// 주의: 강사 공지(/announcements)는 아직 저장소에 서버 함수·테이블·화면이 없습니다. 아래 경로 이름은 제가 정한 가정이며,
// 지금 이 표는 "공지 자원이 생기면 이 ID로 구별한다"는 표시입니다. 기존 메모 주소(/api/notes 계열)는 바꾸지 않았습니다.

// 자원 ID 이름은 판정 응답의 규칙 이름과 같은 모양(영문 소문자로 시작, 소문자·숫자·_.-)으로 맞췄습니다.
export const RESOURCES = Object.freeze([
  Object.freeze({
    id: 'vault.memo',
    zone: 'memo',
    label: '내 메모',
    basePaths: Object.freeze(['/notes']), // 서버 함수 주소는 /api/notes 이고, 판정 요청에는 /api 없이 올 수도 있어 둘 다 읽습니다.
  }),
  Object.freeze({
    id: 'vault.announcement',
    zone: 'announcement',
    label: '강사 공지',
    basePaths: Object.freeze(['/announcements']),
  }),
]);

const METHODS = Object.freeze(['GET', 'POST', 'PUT', 'DELETE']);
// 자료 하나를 가리키는 마지막 조각: 표기 그대로의 ':id' 이거나 영문·숫자·_·- 한 조각입니다. '.', '%', '/', '?'는 받지 않습니다.
const ID_SEGMENT = /^(?::id|[A-Za-z0-9_-]{1,64})$/u;
// 기능 이름으로 보이는 조각은 자료 번호가 될 수 없습니다. (이 표에 :id 와 같은 깊이의 기능 경로는 하나도 없습니다.)
const FUNCTION_WORDS = Object.freeze(['export', 'import', 'search', 'share', 'bulk', 'all', 'admin', 'download', 'publish',
  'new', 'list', 'count', 'stats', 'backup', 'restore', 'archive']);
const isDataId = (segment) => ID_SEGMENT.test(segment) && !FUNCTION_WORDS.includes(segment.toLowerCase());

// "GET /notes/:id" 같은 route 와 "/notes/abc" 같은 path 를 모두 받습니다. 모양이 이상하면 null 입니다.
function readTarget(method, routeOrPath) {
  if (typeof routeOrPath !== 'string' || routeOrPath.length === 0 || routeOrPath.length > 200) return null;
  let verb = method;
  let path = routeOrPath;
  const space = routeOrPath.indexOf(' ');
  if (space !== -1) {
    verb = routeOrPath.slice(0, space);
    path = routeOrPath.slice(space + 1);
    if (typeof method === 'string' && method !== verb) return null; // 동작이 두 군데에서 다르면 믿지 않습니다.
  }
  if (!METHODS.includes(verb) || !path.startsWith('/') || path.includes('//') || /[?#%\\\s]/u.test(path)) return null;
  const clean = path.startsWith('/api/') ? path.slice(4) : path; // 서버 함수 주소의 /api 접두는 읽기만 하고 바꾸지 않습니다.
  return { verb, parts: clean.split('/').slice(1) };
}

// 자원 ID 찾기: { id, zone, label, action, scope } 또는 null.
//   action: GET=read, POST=create, PUT=update, DELETE=delete
//   scope : 'collection'(목록·추가) | 'item'(한 건)
export function resourceFor(method, routeOrPath) {
  const target = readTarget(method, routeOrPath);
  if (!target) return null;
  const { verb, parts } = target;
  for (const resource of RESOURCES) {
    for (const base of resource.basePaths) {
      const baseParts = base.split('/').slice(1);
      if (parts.length < baseParts.length || !baseParts.every((part, index) => parts[index] === part)) continue;
      const rest = parts.slice(baseParts.length);
      const scope = rest.length === 0 ? 'collection' : rest.length === 1 && isDataId(rest[0]) ? 'item' : null;
      if (scope === null) return null; // 구역 이름은 맞지만 그 아래 모양이 틀리면 어느 자원도 아닙니다.
      // 목록 주소에는 한 건 전용 동작이 없습니다. 모양에 맞지 않는 조합은 구별하지 않습니다.
      if (scope === 'collection' && !['GET', 'POST'].includes(verb)) return null;
      if (scope === 'item' && !['GET', 'PUT', 'DELETE'].includes(verb)) return null;
      const action = { GET: 'read', POST: 'create', PUT: 'update', DELETE: 'delete' }[verb];
      return Object.freeze({ id: resource.id, zone: resource.zone, label: resource.label, action, scope });
    }
  }
  return null;
}

function selfCheck(write) {
  const cases = [
    ['GET', 'GET /notes', 'vault.memo'],
    ['POST', 'POST /notes', 'vault.memo'],
    ['GET', 'GET /notes/:id', 'vault.memo'],
    ['PUT', '/api/notes/3f2b8c1e-0000-4000-8000-000000000000', 'vault.memo'],
    ['DELETE', 'DELETE /api/notes/:id', 'vault.memo'],
    ['GET', 'GET /announcements', 'vault.announcement'],
    ['GET', 'GET /announcements/:id', 'vault.announcement'],
    ['PUT', 'PUT /announcements/:id', 'vault.announcement'],
    ['POST', 'POST /announcements', 'vault.announcement'],
    ['GET', '/admin/users', null],
    ['GET', '/notes/../announcements', null],
    ['GET', '/notes/%2e%2e', null],
    ['GET', '/notes/a/b', null],
    ['GET', '/notes/export', null],
    ['GET', '/notes/Export', null],
    ['PUT', '/announcements/export', null],
    ['GET', '/notes/:id/export', null],
    ['GET', '/notes?export=1', null],
    ['PUT', 'PUT /notes', null],
    ['GET', 'POST /notes', null],
    ['GET', '/notesx', null],
    ['GET', undefined, null],
  ];
  write('자원 ID 표\n');
  for (const resource of RESOURCES) write(`  ${resource.id} · ${resource.label} · ${resource.basePaths.join(', ')}\n`);
  write('요청별 자원 ID\n');
  let bad = 0;
  for (const [method, target, expected] of cases) {
    const found = resourceFor(method, target);
    const got = found ? found.id : null;
    const ok = got === expected;
    if (!ok) bad += 1;
    const detail = found ? `${found.zone}/${found.scope}/${found.action}` : '구별 안 됨';
    write(`  ${ok ? '맞음' : '다름'} · ${method} ${String(target)} -> ${got ?? '없음'} (${detail})\n`);
  }
  write(bad === 0 ? '모든 요청이 기대한 자원 ID로 나왔습니다.\n' : `기대와 다른 결과 ${bad}건\n`);
  return bad;
}

// 직접 실행하면 표와 시험 요청의 결과를 보여 줍니다: node src/resources.mjs
// (판정기가 이 파일을 불러올 때는 node:* 모듈을 읽지 않도록, 직접 실행일 때만 동적으로 불러옵니다.)
const entry = typeof process !== 'undefined' ? process.argv?.[1] : undefined;
if (entry) {
  const { fileURLToPath } = await import('node:url');
  const { resolve } = await import('node:path');
  if (resolve(entry) === resolve(fileURLToPath(import.meta.url))) {
    if (selfCheck((text) => process.stdout.write(text)) > 0) process.exitCode = 1;
  }
}
