// 몰래 심어진 프로그램(persistence) 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다
// (심판이 인터넷 없이 이 파일만 가져가도 실행되도록). 경보 원본은 고치지 않고, 반환에 경보 속 경로나 문구를 그대로 옮기지 않습니다.
// 순서: 경보 설명의 문장마다 패턴과 맞는지 보고 → 패턴과 얼마나 뚜렷하게 맞는지로 확신도(0~1)를 매기고
// → 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.

// xdr/persistence/patterns.json 의 패턴을 옮겨 적은 상수입니다(이름·근거는 같고, 찾는 조건은 정규식으로 적었습니다).
// 근거: MITRE ATT&CK T1543(시스템 프로세스 생성·변경), T1053(예약 작업), T1547.001(시작 폴더 항목). 근거가 없는 패턴은 넣지 않습니다.
// 조건은 한 문장 안에서 따집니다. "서명된", "읽기만", "그대로", "없습니다" 같은 정상 표현이 있는 문장은 판단 근거로 쓰지 않습니다.
const PATTERNS = [
  {
    id: 'unsigned-new-service',
    name: '서명 없는 새 서비스 등록',
    evidence: 'MITRE T1543: 공격자는 서비스 같은 시스템 프로세스를 새로 만들거나 바꿔 재부팅 뒤에도 악성 프로그램이 다시 실행되게 한다.',
    match: /서명\s*없는\s*(?:새\s*)?서비스|새\s*서비스|평소 목록에 없는 서비스|서비스\s*실행 파일이 바뀌|서비스\s*등록/u,
  },
  {
    id: 'unfamiliar-scheduled-task',
    name: '낯선 예약 작업',
    evidence: 'MITRE T1053: 공격자는 예약 작업을 만들어 악성 프로그램을 정해 둔 때마다 반복해서 실행시키고 계속 남아 있는다.',
    match: /예약\s*작업.*(?:처음 보는|임의 문자열|수업 시간 밖|임시 폴더)|(?:처음 보는|임의 문자열|수업 시간 밖|임시 폴더).*예약\s*작업/u,
  },
  {
    id: 'startup-folder-change',
    name: '시작 폴더에 평소 목록에 없는 항목 추가',
    evidence: 'MITRE T1547.001: 공격자는 시작 폴더에 프로그램을 넣어 사용자가 로그인할 때마다 자동으로 실행되게 한다.',
    match: /시작\s*(?:폴더|프로그램|항목).*(?:평소 목록에 없|추가됐|같은 임시 파일|함께 가리)/u,
  },
];

// 정상 표현: 이 표현이 있는 문장은 공격 근거로 세지 않습니다.
const NORMAL_SENTENCE = /서명된|읽기만|그대로입니다|(?:등록|실행|변경|추가)(?:은|는|이)?\s*없|평소 시각|평소 저장소/u;
// 약한 신호: 같은 공격과 관련은 있지만 뚜렷한 조건은 아닌 표현.
const WEAK_WORDS = /서비스|예약|시작\s*(?:폴더|프로그램|항목)|임시 폴더|서명/u;
const TEMP_PATH = /[\\/]Temp[\\/]/iu;
const STARTUP_PATH = /Start Menu[\\/]Programs[\\/]Startup/iu;

// 경계값은 연습 경보의 분포(명확 수준 10~12, 애매 수준 5~8, 정상 수준 2~3)에 맞춘 제가 정한 시작값입니다.
// MITRE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다. 수준 4·9 처럼 비어 있는 구간은 애매한 쪽(alert)으로 둡니다.
export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
export const NORMAL_MAX_LEVEL = 3;
export const CLEAR_LEVEL = 10;
const REPEAT_COUNT = 3;

const clamp = (value) => Math.min(1, Math.max(0, Math.round(value * 100) / 100));

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
    const path = typeof alert?.data?.path === 'string' ? alert.data.path.slice(0, 400) : '';
    const sentences = description.split(/[.。!?]\s*/u).map((s) => s.trim()).filter(Boolean);
    const tempPath = TEMP_PATH.test(path);
    const startupPath = STARTUP_PATH.test(path);

    // 1) 뚜렷한 신호: 정상 표현이 없는 문장 안에서 패턴의 조건이 맞는지.
    const hits = PATTERNS.filter((pattern) => sentences.some((s) => !NORMAL_SENTENCE.test(s) && pattern.match.test(s)));
    if (hits.length > 0) {
      // 패턴이 여럿 겹칠수록, 임시 폴더·시작 폴더 경로나 반복·높은 규칙 수준이 겹칠수록 더 뚜렷합니다.
      let confidence = 0.9;
      if (hits.length > 1) confidence += 0.04;
      if (tempPath || startupPath) confidence += 0.02;
      if (count !== null && count >= REPEAT_COUNT) confidence += 0.02;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.02;
      return { action: 'block', confidence: clamp(Math.min(confidence, 0.99)), reason: hits.map((pattern) => pattern.name).join(' · ') };
    }

    // 2) 약한 신호: 서비스·예약·시작 항목 얘기는 있지만 뚜렷한 조건은 아닌 경우.
    const weak = sentences.some((s) => WEAK_WORDS.test(s));
    let confidence;
    if ((level !== null && level <= NORMAL_MAX_LEVEL) || (level === null && !weak && !tempPath)) {
      confidence = 0.05; // 낮은 규칙 수준이거나 관련 표현이 없는 정상 이벤트
    } else {
      // 애매한 경우: 수준 4~9 이거나 약한 신호가 있으면 alert 범위(0.5 이상 0.85 미만)에서 얼마나 닮았는지로 나눕니다.
      confidence = 0.5;
      if (weak) confidence += 0.05;
      if (tempPath) confidence += 0.07;
      if (level !== null && level >= 7) confidence += 0.03;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.07; // 수준은 높지만 뚜렷한 조건이 없으면 block 하지 않고 alert 로 둡니다.
      confidence = Math.min(confidence, 0.8);
    }
    const final = clamp(confidence);
    if (final >= ALERT_AT) {
      // 가장 가까운 패턴 이름: 예약 얘기면 예약 작업, 시작 얘기면 시작 폴더, 그 밖에는 서비스.
      const text = sentences.join(' ');
      const near = /예약/u.test(text) ? PATTERNS[1] : /시작\s*(?:폴더|프로그램|항목)/u.test(text) ? PATTERNS[2] : PATTERNS[0];
      return { action: 'alert', confidence: final, reason: `${near.name} 패턴과 일부만 맞습니다(뚜렷한 조건은 아님)` };
    }
    return { action: 'record', confidence: final, reason: '다시 켜도 남도록 심긴 서비스·예약 작업 형태와 맞는 패턴이 없는 정상 이벤트입니다' };
  } catch {
    // 어떤 입력에도 예외를 밖으로 내보내지 않습니다. 판단하지 못한 경보는 사람이 보도록 alert 로 둡니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '경보를 읽지 못해 사람이 확인하도록 알립니다' };
  }
}
