// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.

const MAX_SUB_LENGTH = 128;
const WINDOW_MS = 10 * 60 * 1000; // 10분 구간(양 끝 시각 포함)
const BURST_LIMIT = 120; // 120건까지는 정상, 120건을 넘으면 폭주

// 입력 처리: 사건 하나에서 시각·요청 종류·가명 사용자(sub) 세 값만 꺼냅니다.
// 그 밖의 필드(메모 내용, 토큰, 실명 등)는 읽지도, 저장하지도, 출력하지도 않습니다.
// 모양이 이상한 사건은 추측하지 않고 null로 버립니다.
export function readEvent(event) {
  if (event === null || typeof event !== 'object') return null;
  const { at, method, identity } = event;
  if (typeof at !== 'string') return null;
  const time = Date.parse(at);
  if (!Number.isFinite(time)) return null;
  if (typeof method !== 'string') return null;
  if (identity === null || typeof identity !== 'object') return null;
  const { sub } = identity;
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > MAX_SUB_LENGTH) return null;
  return { time, method: method.toUpperCase(), sub };
}

// 배열 전체를 읽어 시간순으로 정렬한 세 값짜리 사건 목록을 돌려줍니다.
export function readEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const read = [];
  for (const event of events) {
    const item = readEvent(event);
    if (item) read.push(item);
  }
  read.sort((a, b) => a.time - b.time);
  return read;
}

// 탐지 규칙 하나: 같은 sub의 GET이 어느 10분 구간에서든 120건을 넘으면 폭주 조회입니다.
// 사용자별로 따로 세고(합산하지 않음), 10분 밖의 사건은 같은 묶음으로 세지 않습니다.
// 폭주가 가장 먼저 완성된 시각의 sub 하나를 돌려주고, 없으면 null입니다.
function findBurst(read) {
  const bySub = new Map();
  for (const item of read) {
    if (item.method !== 'GET') continue;
    if (!bySub.has(item.sub)) bySub.set(item.sub, []);
    bySub.get(item.sub).push(item.time);
  }
  let found = null;
  for (const [sub, times] of bySub) {
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] > WINDOW_MS) start += 1;
      if (end - start + 1 > BURST_LIMIT) {
        if (!found || times[end] < found.time) found = { sub, time: times[end] };
        break;
      }
    }
  }
  return found ? found.sub : null;
}

export function detect(events) {
  const burstSub = findBurst(readEvents(events));
  if (burstSub !== null) {
    return { action: 'propose_revocation', reasonCode: 'burst_read', subject: burstSub };
  }
  return { action: 'observe' };
}
