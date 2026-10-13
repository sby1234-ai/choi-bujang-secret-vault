// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 규칙은 하나씩 추가합니다. RULE_IDS 에는 실제로 구현한 규칙만 적습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { resourceFor } from './resources.mjs';

export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_known_resource', 'zone_memo_own', 'zone_announcement_write']);

// 계약(docs/DECIDER_REQUEST.md)이 정한 요청 이름 18개입니다. 이 밖의 이름은 엔진이 만든 값이 아닙니다.
const REQUEST_KEYS = Object.freeze([
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route',
  'queryLength', 'querySha256', 'at', 'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
]);
const SIGNAL_KEYS = Object.freeze(['source', 'region', 'network', 'hour']);
const EVENT_KEYS = Object.freeze(['kind', 'ageSeconds', 'count']);
const MAX_EVENTS = 12;
const MAX_AUTH_AGE_SECONDS = 900;
const LABEL = /^[a-z][a-z0-9_.-]{0,31}$/u;

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const hasExactKeys = (value, keys) => isPlainObject(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isCount = (value) => Number.isInteger(value) && value >= 0;

// 판정기가 읽는 접속 정보의 출처 구분입니다. 값을 만들어 채우지 않고, 믿을 수 없거나 없는 값은 null 로 남깁니다.
//  - origin 'engine_none'   : 엔진이 신호가 없다고 알린 경우(실제 경로). 지역·시각·네트워크는 모두 알 수 없음.
//  - origin 'judge_fixture' : 엔진이 심판의 가상 접속 사건으로 넘긴 경우. 시험용 값이며 실제 위치 증거가 아닙니다.
//  - origin 'untrusted'     : 계약에 없는 이름이 섞였거나, 출처 표시가 없거나 알 수 없는 경우. 어떤 값도 쓰지 않습니다.
// 브라우저·클라이언트 헤더처럼 계약에 없는 입력은 읽지 않으며, 있으면 요청 전체를 untrusted 로 봅니다.
export function readAccessContext(request) {
  const empty = (origin, problems) => ({
    origin, trusted: false, realLocationEvidence: false,
    region: null, network: null, hour: null,
    events: [], eventsKnown: false,
    stepUp: { verified: false, authAgeSeconds: null },
    problems,
  });
  if (!isPlainObject(request)) return empty('untrusted', ['request_not_object']);

  const problems = [];
  const extra = Object.keys(request).filter((key) => !REQUEST_KEYS.includes(key));
  if (extra.length > 0) problems.push('unexpected_request_keys');
  if (request.schema !== 'aleph.decision.v1') problems.push('schema_mismatch');
  if (!hasExactKeys(request.signals, SIGNAL_KEYS)) problems.push('signals_shape_invalid');
  if (problems.length > 0) return empty('untrusted', problems);

  const { source, region, network, hour } = request.signals;
  // stepUp 은 엔진 값만 쓰되 모양이 틀리면 확인 안 됨으로 봅니다. 이 값만으로 재인증 확인을 건너뛰지 않습니다.
  const stepUpOk = hasExactKeys(request.stepUp, ['verified', 'authAgeSeconds'])
    && ((request.stepUp.verified === false && request.stepUp.authAgeSeconds === null)
      || (request.stepUp.verified === true && Number.isInteger(request.stepUp.authAgeSeconds)
        && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= MAX_AUTH_AGE_SECONDS));
  const stepUp = stepUpOk
    ? { verified: request.stepUp.verified, authAgeSeconds: request.stepUp.authAgeSeconds }
    : { verified: false, authAgeSeconds: null };
  if (!stepUpOk) problems.push('step_up_shape_invalid');

  if (source === 'none') {
    // 신호 없음: 실제 경로의 값입니다. 지역·네트워크는 "unknown"이어야 하고 시각은 없어야 합니다.
    return { ...empty('engine_none', problems), stepUp };
  }
  if (source !== 'judge_fixture') {
    return { ...empty('untrusted', [...problems, 'signal_source_unknown']), stepUp };
  }

  // 심판의 가상 접속 사건: 값마다 모양을 확인하고, 틀리거나 "unknown"이면 알 수 없음(null)으로 둡니다.
  const label = (value) => (typeof value === 'string' && value !== 'unknown' && LABEL.test(value) ? value : null);
  const parsedRegion = label(region);
  const parsedNetwork = label(network);
  const parsedHour = Number.isInteger(hour) && hour >= 0 && hour <= 23 ? hour : null;
  if (region !== 'unknown' && parsedRegion === null) problems.push('region_invalid');
  if (network !== 'unknown' && parsedNetwork === null) problems.push('network_invalid');
  if (parsedHour === null) problems.push('hour_invalid');

  let events = [];
  let eventsKnown = false;
  const list = request.recentEvents;
  const eventsOk = Array.isArray(list) && list.length <= MAX_EVENTS
    && list.every((item) => hasExactKeys(item, EVENT_KEYS)
      && typeof item.kind === 'string' && LABEL.test(item.kind) && isCount(item.ageSeconds) && isCount(item.count));
  if (eventsOk) {
    events = list.map((item) => ({ kind: item.kind, ageSeconds: item.ageSeconds, count: item.count }));
    eventsKnown = true;
  } else {
    problems.push('recent_events_invalid');
  }

  return {
    origin: 'judge_fixture', trusted: true, realLocationEvidence: false,
    region: parsedRegion, network: parsedNetwork, hour: parsedHour,
    events, eventsKnown, stepUp, problems,
  };
}

// 규칙 step_up_required(복합 사건): 등록된 기기에서 아래 세 가지가 한꺼번에 맞을 때만 추가 확인(step_up)을 요구합니다.
//   1) 평소와 다른 시각  2) 처음 보는(unusual) 네트워크  3) 짧은 시간에 많은 자료를 읽은 사건
// 지역은 이 조건에 쓰지 않습니다. 지역 하나로는 어떤 결정도 바꾸지 않고, 이 규칙은 deny 가 아니라 step_up 만 만들어서
// 정상 사용자를 영구 차단하지 않습니다. 다시 확인한 요청(stepUp.verified)은 허용합니다.
// 아래 숫자·이름은 문서에 정해진 값이 없어 제가 정한 시작값입니다. 운영 기준이 생기면 이 상수만 바꿉니다.
export const OFF_HOURS = Object.freeze({ from: 0, to: 5 }); // 평소와 다른 시각: 0~5시(포함)
const UNUSUAL_NETWORK = 'unusual'; // 연습 가상 사건이 처음 보는 네트워크를 알리는 표기
export const HEAVY_READ_COUNT = 10; // 최근 사건 건수 합계가 이 값 이상이면 "많이 읽음"
export const HEAVY_READ_WINDOW_SECONDS = 3600; // "갑자기": 이 시간 안의 사건만 셈
const STEP_UP_REASON = 'step_up_required';

function isComplexUnusualAccess(context) {
  // 출처가 심판의 가상 사건으로 확인되고 값이 모두 읽힌 경우에만 판단합니다. 알 수 없는 값은 이상으로 치지 않습니다.
  if (context.origin !== 'judge_fixture' || !context.trusted || !context.eventsKnown) return false;
  const offHours = context.hour !== null && context.hour >= OFF_HOURS.from && context.hour <= OFF_HOURS.to;
  const newNetwork = context.network === UNUSUAL_NETWORK;
  const heavyRead = context.events
    .filter((event) => event.ageSeconds <= HEAVY_READ_WINDOW_SECONDS)
    .reduce((total, event) => total + event.count, 0) >= HEAVY_READ_COUNT;
  return offHours && newNetwork && heavyRead;
}

// 구역 규칙에 쓰는 요청 확인입니다. 엔진이 확인해 넘긴 값(subjectId, deviceId, method, route, path)만 읽고, 쿼리(queryLength·querySha256)는
// 어떤 기능을 고르는 데 쓰지 않습니다. 자료 하나를 고르는 것은 경로의 :id 자리 하나뿐입니다.
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const validRequester = (request) => typeof request.subjectId === 'string' && request.subjectId.length > 0 && request.subjectId.length <= 200
  && !/[\u0000-\u001f]/u.test(request.subjectId) && typeof request.deviceId === 'string' && DEVICE_ID.test(request.deviceId);

// 정확한 경로 확인: route 와 path 가 둘 다 같은 자원·같은 동작을 가리킬 때만 그 자원으로 인정합니다. 하나라도 어긋나거나 모르면 null.
function resolveResource(request) {
  const byRoute = resourceFor(request.method, request.route);
  const byPath = resourceFor(request.method, request.path);
  if (!byRoute || !byPath) return null;
  if (byRoute.id !== byPath.id || byRoute.scope !== byPath.scope || byRoute.action !== byPath.action) return null;
  return byRoute;
}

// 규칙 device_registered: 엔진이 알려 준 deviceRegistered 가 정확히 true 일 때만 허용합니다.
// false 이거나 값이 없거나 true 가 아닌 다른 값이면 거부합니다. 이 규칙을 먼저 확인합니다.
// 구역 규칙(그다음):
//   zone_known_resource      : 요청자(subjectId·deviceId) 모양이 맞고 정확한 경로가 표(src/resources.mjs)의 자원이어야 합니다. 모르면 거부합니다.
//   zone_announcement_write  : 강사 공지 구역은 읽기·쓰기 모두 거부합니다(내 메모 구역과 섞이지 않게 닫아 둠).
//                              현재 계약에는 강사 역할(request.role 등)이 없어서 강사임을 확인할 수 없으므로, 누구에게도 열지 않습니다(안전한 쪽).
//   zone_memo_own            : 내 메모의 읽기·수정은 이 구역에서 허용합니다. 판정 요청에는 메모 소유자 정보가 없어서
//                              "내 메모인지"는 판정기가 아니라 최종 자료 API(owner_id 검사)가 확인합니다.
// 그다음 step_up_required: 복합 사건이면 추가 확인을 요구하고, 이미 다시 확인한 요청이면 허용합니다.
export async function decide(request) {
  const respond = (decision, reasonCode, ruleIds) => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision, reasonCode, ruleIds,
  });
  if (request?.deviceRegistered !== true) return respond('deny', 'device_not_registered', ['device_registered']);

  if (!validRequester(request)) return respond('deny', 'request_invalid', ['zone_known_resource']);
  const resource = resolveResource(request);
  if (resource === null) return respond('deny', 'resource_unknown', ['zone_known_resource']);
  if (resource.zone === 'announcement') {
    return respond('deny', 'zone_forbidden', ['zone_announcement_write']);
  }
  const zoneRule = resource.zone === 'memo' && (resource.action === 'read' || resource.action === 'update')
    ? 'zone_memo_own' : 'zone_known_resource';

  const context = readAccessContext(request);
  if (isComplexUnusualAccess(context)) {
    // 엔진이 검증해 넘긴 stepUp 값만 씁니다. 모양이 틀리면 확인 안 됨으로 읽힙니다.
    if (context.stepUp.verified === true) return respond('allow', 'approved', ['device_registered', zoneRule, 'step_up_required']);
    return respond('step_up', STEP_UP_REASON, ['step_up_required']);
  }
  return respond('allow', 'approved', ['device_registered', zoneRule]);
}
