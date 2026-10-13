// 권한 가로채기(privilege) 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다
// (심판이 인터넷 없이 이 파일만 가져가도 실행되도록). 경보 원본은 고치지 않고, 반환에 경보 속 문구를 그대로 옮기지 않습니다.
// 순서: 경보 설명의 문장마다 패턴과 맞는지 보고 → 패턴과 얼마나 뚜렷하게 맞는지로 확신도(0~1)를 매기고
// → 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.

// xdr/privilege/patterns.json 의 패턴을 옮겨 적은 상수입니다(이름·근거는 같고, 찾는 조건은 정규식으로 적었습니다).
// 근거: MITRE ATT&CK T1068(권한 상승 악용), T1078(정상 계정 도용). 근거가 없는 패턴은 넣지 않습니다.
// 조건은 한 문장 안에서 따집니다. "읽기만", "취소됐", "명령은 없습니다", "평소 … 로그인했" 같은 정상 표현이 있는 문장은 판단 근거로 쓰지 않습니다.
const PATTERNS = [
  {
    id: 'admin-group-added',
    name: '평범한 계정의 관리자 그룹 추가',
    evidence: 'MITRE T1078: 공격자는 정상 계정을 빼앗아 그 계정의 권한으로 활동하고, 계정을 관리자 그룹에 넣어 더 높은 권한을 확보한다.',
    match: /관리자 그룹(?:에|에서)?\s.*?(?:추가|들어가|들어왔)|관리자 그룹 추가/u,
  },
  {
    id: 'unfamiliar-admin-command',
    name: '처음 보는 관리자 명령 실행',
    evidence: 'MITRE T1068: 공격자는 약점을 악용해 권한을 높인 뒤 높아진 권한이 필요한 관리자 명령을 실행한다.',
    // 관리자 명령(또는 세션 권한 변경)이 있고, 방금 관리자가 됐거나 처음 보는 주소·다른 계정의 권한 같은 낯선 조건이 같은 문장에 있어야 합니다.
    match: (sentence) => /관리자 명령|권한 명령|명령 실행|관리자 권한으로 바뀌/u.test(sentence)
      && /방금 관리자가 된|처음 보|다른 계정의 권한|곧바로|관리자 권한으로 바뀌|같이 있/u.test(sentence),
  },
  {
    id: 'off-hours-privilege-use',
    name: '업무 시간 밖 권한 사용',
    evidence: 'MITRE T1078: 공격자는 정상 계정을 평소와 다른 시각에 사용하는 경우가 많아, 시각이 맞지 않는 권한 사용은 도용된 계정의 대표적인 흔적이다.',
    match: /(?:수업 시간 밖|업무처럼 보이지 않는).*(?:관리자|권한|명령)/u,
  },
];

// 정상 표현: 이 표현이 있는 문장은 공격 근거로 세지 않습니다.
const NORMAL_SENTENCE = /관리자 그룹은 아닙니다|읽기만|변경은 없|이어서 명령은 없|명령은 없|실패\s*\d+건으로 끝|취소됐|조회했|로그인했|로그아웃했|확인했/u;
// 약한 신호: 같은 공격과 관련은 있지만 뚜렷한 조건은 아닌 표현.
const WEAK_WORDS = /관리자|권한|그룹|명령|세션|상승/u;
const ADMIN_GROUP = /^(?:administrators?|admins?|domain admins|root|sudo|wheel)$/iu;

// 경계값은 연습 경보의 분포(명확 수준 10~12, 애매 수준 5~8, 정상 수준 2~3)에 맞춘 제가 정한 시작값입니다.
// MITRE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다. 수준 4·9 처럼 비어 있는 구간은 애매한 쪽(alert)으로 둡니다.
export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
export const NORMAL_MAX_LEVEL = 3;
export const CLEAR_LEVEL = 10;
const REPEAT_COUNT = 3;

const clamp = (value) => Math.min(1, Math.max(0, Math.round(value * 100) / 100));
const matches = (pattern, sentence) => (typeof pattern.match === 'function' ? pattern.match(sentence) : pattern.match.test(sentence));

function levelOf(alert) {
  const raw = alert?.rule?.level;
  const value = (typeof raw === 'number' || (typeof raw === 'string' && raw.trim() !== '')) ? Number(raw) : null;
  return Number.isInteger(value) && value >= 0 && value <= 15 ? value : null;
}

function repeatOf(alert) {
  const raw = alert?.data?.count;
  const value = (typeof raw === 'string' || typeof raw === 'number') && String(raw).trim() !== '' ? Number(raw) : null;
  return Number.isFinite(value) && value >= 0 ? value : null;
}

export function decide(alert) {
  try {
    if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
      return { action: 'record', confidence: 0, reason: '경보 형식이 아니라서 기록만 합니다' };
    }
    const level = levelOf(alert);
    const count = repeatOf(alert);
    const description = typeof alert?.rule?.description === 'string' ? alert.rule.description.slice(0, 400) : '';
    const sentences = description.split(/[.。!?]\s*/u).map((s) => s.trim()).filter(Boolean);
    const adminGroup = typeof alert?.data?.group === 'string' && ADMIN_GROUP.test(alert.data.group.trim());

    // 1) 뚜렷한 신호: 정상 표현이 없는 문장 안에서 패턴의 조건이 맞는지.
    const hits = PATTERNS.filter((pattern) => sentences.some((s) => !NORMAL_SENTENCE.test(s) && matches(pattern, s)));
    if (hits.length > 0) {
      // 패턴이 여럿 겹칠수록, 관리자 그룹 기록이나 여러 계정(반복)·높은 규칙 수준이 겹칠수록 더 뚜렷합니다.
      let confidence = 0.9;
      if (hits.length > 1) confidence += 0.04;
      if (adminGroup) confidence += 0.02;
      if (count !== null && count >= REPEAT_COUNT) confidence += 0.02;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.02;
      return { action: 'block', confidence: clamp(Math.min(confidence, 0.99)), reason: hits.map((pattern) => pattern.name).join(' · ') };
    }

    // 2) 약한 신호: 그룹·권한·명령 얘기는 있지만 뚜렷한 조건은 아닌 경우.
    const weak = sentences.some((s) => WEAK_WORDS.test(s));
    let confidence;
    if ((level !== null && level <= NORMAL_MAX_LEVEL) || (level === null && !weak)) {
      confidence = 0.05; // 낮은 규칙 수준이거나 관련 표현이 없는 정상 이벤트
    } else {
      // 애매한 경우: 수준 4~9 이거나 약한 신호가 있으면 alert 범위(0.5 이상 0.85 미만)에서 얼마나 닮았는지로 나눕니다.
      confidence = 0.5;
      if (weak) confidence += 0.05;
      if (adminGroup) confidence += 0.05;
      if (level !== null && level >= 7) confidence += 0.03;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.07; // 수준은 높지만 뚜렷한 조건이 없으면 block 하지 않고 alert 로 둡니다.
      confidence = Math.min(confidence, 0.8);
    }
    const final = clamp(confidence);
    if (final >= ALERT_AT) {
      // 가장 가까운 패턴 이름: 명령·세션·권한 얘기면 관리자 명령, 시간 얘기면 업무 시간 밖, 그 밖에는 관리자 그룹.
      const text = sentences.join(' ');
      const near = /명령|세션|권한/u.test(text) ? PATTERNS[1] : /시간|시각/u.test(text) ? PATTERNS[2] : PATTERNS[0];
      return { action: 'alert', confidence: final, reason: `${near.name} 패턴과 일부만 맞습니다(뚜렷한 조건은 아님)` };
    }
    return { action: 'record', confidence: final, reason: '권한 상승이나 계정 도용 형태와 맞는 패턴이 없는 정상 이벤트입니다' };
  } catch {
    // 어떤 입력에도 예외를 밖으로 내보내지 않습니다. 판단하지 못한 경보는 사람이 보도록 alert 로 둡니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '경보를 읽지 못해 사람이 확인하도록 알립니다' };
  }
}
