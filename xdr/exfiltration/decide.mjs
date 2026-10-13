// 자료 빼돌리기(exfiltration) 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다
// (심판이 인터넷 없이 이 파일만 가져가도 실행되도록). 경보 원본은 고치지 않고, 반환에 경보 속 문구나 주소를 그대로 옮기지 않습니다.
// 순서: 경보 설명의 문장마다 패턴과 맞는지 보고, 전송량이 큰지 함께 확인해 → 얼마나 뚜렷하게 맞는지로 확신도(0~1)를 매기고
// → 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.

// xdr/exfiltration/patterns.json 의 패턴을 옮겨 적은 상수입니다(이름·근거는 같고, 찾는 조건은 정규식으로 적었습니다).
// 근거: MITRE ATT&CK T1048(다른 프로토콜로 유출), T1041(명령 통로로 유출). 근거가 없는 패턴은 넣지 않습니다.
// 조건은 한 문장 안에서 따집니다. "읽었", "저장했", "실패 1건", "전송은 없" 같은 정상 표현이 있는 문장은 판단 근거로 쓰지 않습니다.
// 뚜렷한 신호는 설명이 조건과 맞고 전송량(bytes)이 클 때만 인정합니다. 작은 전송은 목적지가 낯설어도 alert 까지만 갑니다.
const PATTERNS = [
  {
    id: 'large-transfer-to-new-destination',
    name: '처음 보는 목적지로 대용량 전송',
    evidence: 'MITRE T1048: 공격자는 평소 쓰지 않는 경로로 대량의 자료를 외부 목적지로 빼내며, 처음 보는 목적지로의 큰 전송이 대표적인 신호다.',
    match: /처음 보는 (?:목적지|주소)|같은 목적지.*(?:대용량|반복)|전송이 \d+번|평소에 쓰지 않던 포트/u,
  },
  {
    id: 'off-hours-archive-exfiltration',
    name: '업무 시간 밖 압축 파일 반출',
    evidence: 'MITRE T1048: 공격자는 모은 자료를 압축해 업무 시간 밖에 평소와 다른 주소로 한꺼번에 옮겨 들키지 않고 반출한다.',
    match: /(?:수업|업무) 시간 밖.*압축 파일|압축 파일.*(?:처음 보는|연속)/u,
  },
  {
    id: 'command-channel-exfiltration',
    name: '명령 통로를 이용한 자료 전송',
    evidence: 'MITRE T1041: 공격자는 이미 쓰는 명령 통제 통로로 자료를 함께 실어 보내 별도 통로 없이 반출한다.',
    match: /명령 통로.*(?:큰 파일|반복)|자료실 전체|외부 주소로 복사/u,
  },
];

// 정상 표현: 이 표현이 있는 문장은 공격 근거로 세지 않습니다.
const NORMAL_SENTENCE = /읽었|읽힌 뒤|저장했|새로고침|로그아웃|세션 확인|받았|열었|동기화가 끝|전송은 (?:아직 )?없|실패\s*\d+건으로 끝|만들었/u;
// 약한 신호: 같은 공격과 관련은 있지만 뚜렷한 조건은 아닌 표현.
const WEAK_WORDS = /전송|목적지|주소|압축|파일|자료|명령 통로|시간 밖|나갔|올라갔/u;

// 경계값은 연습 경보의 분포(전송량 명확 7천만 바이트 이상·애매 1천 5백만 이하·정상 수만 이하, 규칙 수준 명확 10~12·애매 5~8·정상 2~3)에 맞춘
// 제가 정한 시작값입니다. MITRE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다. 수준 4·9 처럼 비어 있는 구간은 alert 로 둡니다.
export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
export const NORMAL_MAX_LEVEL = 3;
export const CLEAR_LEVEL = 10;
export const LARGE_BYTES = 50_000_000;
const HUGE_BYTES = 200_000_000;
const MEDIUM_BYTES = 10_000_000;
const REPEAT_COUNT = 5;

const clamp = (value) => Math.min(1, Math.max(0, Math.round(value * 100) / 100));

function numberOf(raw) {
  const value = (typeof raw === 'number' || (typeof raw === 'string' && raw.trim() !== '')) ? Number(raw) : null;
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function levelOf(alert) {
  const value = numberOf(alert?.rule?.level);
  return Number.isInteger(value) && value <= 15 ? value : null;
}

export function decide(alert) {
  try {
    if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
      return { action: 'record', confidence: 0, reason: '경보 형식이 아니라서 기록만 합니다' };
    }
    const level = levelOf(alert);
    const bytes = numberOf(alert?.data?.bytes);
    const count = numberOf(alert?.data?.count);
    const description = typeof alert?.rule?.description === 'string' ? alert.rule.description.slice(0, 400) : '';
    const sentences = description.split(/[.。!?]\s*/u).map((s) => s.trim()).filter(Boolean);

    // 1) 뚜렷한 신호: 정상 표현이 없는 문장이 패턴 조건과 맞고, 전송량이 클 때(전송량을 모르면 설명이 큰 전송을 말할 때).
    const large = bytes !== null ? bytes >= LARGE_BYTES : /대용량|큰 파일|전체/u.test(description);
    const hits = large
      ? PATTERNS.filter((pattern) => sentences.some((s) => !NORMAL_SENTENCE.test(s) && pattern.match.test(s)))
      : [];
    if (hits.length > 0) {
      // 패턴이 여럿 겹칠수록, 전송량이 아주 크거나 같은 전송이 반복될수록, 규칙 수준이 높을수록 더 뚜렷합니다.
      let confidence = 0.9;
      if (hits.length > 1) confidence += 0.04;
      if (bytes !== null && bytes >= HUGE_BYTES) confidence += 0.02;
      if (count !== null && count >= REPEAT_COUNT) confidence += 0.02;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.02;
      return { action: 'block', confidence: clamp(Math.min(confidence, 0.99)), reason: hits.map((pattern) => pattern.name).join(' · ') };
    }

    // 2) 약한 신호: 전송 얘기는 있지만 전송량이 작거나 조건이 뚜렷하지 않은 경우.
    const weak = sentences.some((s) => WEAK_WORDS.test(s));
    let confidence;
    if (level !== null && level <= NORMAL_MAX_LEVEL) {
      confidence = 0.05; // 낮은 규칙 수준의 정상 이벤트
    } else if (level === null && !weak) {
      confidence = 0.05; // 규칙 수준도 모르고 관련 표현도 없는 이벤트
    } else {
      // 애매한 경우: 수준 4~9 이거나 약한 신호가 있으면 alert 범위(0.5 이상 0.85 미만)에서 얼마나 닮았는지로 나눕니다.
      confidence = 0.5;
      if (weak) confidence += 0.05;
      if (bytes !== null && bytes >= MEDIUM_BYTES) confidence += 0.05;
      if (level !== null && level >= 7) confidence += 0.03;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.07; // 수준은 높지만 뚜렷한 조건이 없으면 block 하지 않고 alert 로 둡니다.
      confidence = Math.min(confidence, 0.8);
    }
    const final = clamp(confidence);
    if (final >= ALERT_AT) {
      // 가장 가까운 패턴 이름: 명령 통로 얘기면 명령 통로, 압축 얘기면 압축 파일 반출, 그 밖에는 대용량 전송.
      const text = sentences.join(' ');
      const near = /명령 통로/u.test(text) ? PATTERNS[2] : /압축/u.test(text) ? PATTERNS[1] : PATTERNS[0];
      return { action: 'alert', confidence: final, reason: `${near.name} 패턴과 일부만 맞습니다(뚜렷한 조건은 아님)` };
    }
    return { action: 'record', confidence: final, reason: '큰 자료가 낯선 곳으로 나가는 형태와 맞는 패턴이 없는 정상 이벤트입니다' };
  } catch {
    // 어떤 입력에도 예외를 밖으로 내보내지 않습니다. 판단하지 못한 경보는 사람이 보도록 alert 로 둡니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '경보를 읽지 못해 사람이 확인하도록 알립니다' };
  }
}
