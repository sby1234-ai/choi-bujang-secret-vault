// 알려진 취약점(known-cve) 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일이나 패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다
// (심판이 인터넷 없이 이 파일만 가져가도 실행되도록). 경보 원본은 고치지 않고, 반환에 경보 속 구문을 그대로 옮기지 않습니다.
// 순서: 경보의 요청 머리글·주소 인자에서 패턴을 찾고 → 패턴과 얼마나 뚜렷하게 맞는지로 확신도(0~1)를 매기고
// → 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.

// xdr/known-cve/patterns.json 의 패턴을 옮겨 적은 상수입니다(이름·근거는 같고, 찾는 조건은 정규식으로 적었습니다).
// 근거: CVE-2021-44228(NVD), MITRE ATT&CK T1190 · T1595.002. 근거가 없는 패턴은 넣지 않습니다.
// 완전한 조회 구문(${jndi:ldap://주소 ...})만 뚜렷한 신호로 보고, jndi 단어·CVE 번호 문구·중괄호 조각은 약한 신호로만 셉니다.
const LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|nis|corba|nds)\s*:\s*\/\/[^\s}]{1,200}/iu;
const PATTERNS = [
  {
    id: 'jndi-lookup-in-header',
    name: '요청 머리글 안의 원격 조회 구문(jndi 형태)',
    evidence: 'CVE-2021-44228: 기록되는 문자열에 ${jndi:ldap://...} 구문을 넣으면 서버가 외부 끝점에서 코드를 불러와 실행할 수 있다.',
    match: LOOKUP,
    where: 'header',
  },
  {
    id: 'jndi-lookup-in-request-argument',
    name: '요청 주소 인자 안의 원격 조회 구문(jndi 형태)',
    evidence: 'MITRE T1190: 외부에 열린 서비스에 알려진 취약점의 공격 입력을 보내는 초기 침투이며, 요청 인자는 그 입력이 들어오는 대표 경로다.',
    match: LOOKUP,
    where: 'argument',
  },
  {
    id: 'vulnerability-scanner-trace',
    name: '알려진 취약점 점검 도구의 흔적',
    evidence: 'MITRE T1595.002: 공격자는 대상 서비스에 알려진 취약점이 있는지 점검 도구로 훑어 본 뒤 악용으로 넘어간다.',
    match: /[?&;](?:probe|scan|scanner)=/iu, // 점검용 인자. 점검 도구와 비슷한 수업용 프로그램 이름만으로는 맞지 않는다.
    where: 'argument',
    onlyWithLookup: true,
  },
];

// 약한 신호: 완전한 구문은 아니지만 같은 공격과 관련된 표기입니다(이것만으로는 block 하지 않습니다).
const WEAK_SIGNALS = [
  /\bjndi\b/iu,
  /CVE-2021-44228/iu,
  /\$\{|\$%7B|%24%7B/iu,
  /\blookup\b/iu,
  /[?&;](?:probe|scan|scanner)=/iu,
];
// 설명 문구의 약한 신호입니다(설명에 "없습니다·아닙니다"가 함께 있으면 공격 근거로 세지 않고 애매함만 남깁니다).
const WEAK_WORDS = /원격\s*조회|조회\s*(?:형태|구문)|CVE-\d{4}-\d+|취약점|중괄호|jndi|점검/iu;
const NEGATED = /아닙니다|없습니다|않았|않습니다|글자만/u;

// 경계값은 연습 경보의 분포(명확 수준 10~13, 애매 수준 5~8, 정상 수준 2~3)에 맞춘 제가 정한 시작값입니다.
// MITRE·CVE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다. 수준 4·9 처럼 비어 있는 구간은 애매한 쪽(alert)으로 둡니다.
export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
export const NORMAL_MAX_LEVEL = 3;
export const CLEAR_LEVEL = 10;
const REPEAT_COUNT = 5;

const HEADER_KEY = /agent|header|referer|referrer|cookie|host|^x-/iu;
const ARGUMENT_KEY = /url|uri|path|query|arg|param/iu;

const clamp = (value) => Math.min(1, Math.max(0, Math.round(value * 100) / 100));

// 요청 값은 한 번 퍼센트 해제한 것과 원문을 모두 살핍니다. 해제가 안 되면 원문만 씁니다.
function views(text) {
  const out = [text];
  try {
    const decoded = decodeURIComponent(text);
    if (decoded !== text) out.push(decoded);
  } catch { /* 해제 불가한 문자열은 원문만 */ }
  return out;
}
const textHas = (text, regex) => views(text).some((view) => regex.test(view));

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

// 경보의 요청 값을 머리글 쪽과 주소 인자 쪽으로 나눠 모읍니다. 값이 문자열이 아니면 건너뜁니다.
function requestValues(alert) {
  const header = [];
  const argument = [];
  const data = alert?.data;
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return { header, argument };
  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== 'string' || value.length > 4000) continue;
    if (HEADER_KEY.test(key)) header.push(value);
    else if (ARGUMENT_KEY.test(key)) argument.push(value);
  }
  return { header, argument };
}

export function decide(alert) {
  try {
    if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
      return { action: 'record', confidence: 0, reason: '경보 형식이 아니라서 기록만 합니다' };
    }
    const level = levelOf(alert);
    const count = repeatOf(alert);
    const { header, argument } = requestValues(alert);
    const description = typeof alert?.rule?.description === 'string' ? alert.rule.description.slice(0, 400) : '';

    // 1) 뚜렷한 신호: 완전한 조회 구문이 머리글·주소 인자에 있는지.
    const lookupPatterns = PATTERNS.filter((pattern) => !pattern.onlyWithLookup);
    const hits = lookupPatterns.filter((pattern) => (pattern.where === 'header' ? header : argument)
      .some((text) => textHas(text, pattern.match)));
    const scanner = PATTERNS.find((pattern) => pattern.onlyWithLookup);
    const scannerTrace = hits.length > 0 && argument.some((text) => textHas(text, scanner.match));

    if (hits.length > 0) {
      // 머리글과 주소 양쪽, 반복, 점검 흔적, 높은 규칙 수준이 겹칠수록 더 뚜렷합니다.
      let confidence = 0.9;
      if (hits.length > 1) confidence += 0.04;
      if (scannerTrace) confidence += 0.02;
      if (count !== null && count >= REPEAT_COUNT) confidence += 0.02;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.02;
      const names = hits.map((pattern) => pattern.name);
      if (scannerTrace) names.push(scanner.name);
      return { action: 'block', confidence: clamp(Math.min(confidence, 0.99)), reason: names.join(' · ') };
    }

    // 2) 약한 신호: 단어·번호 문구·잘린 조각처럼 같은 공격과 관련은 있지만 완전한 구문이 아닌 경우.
    const values = [...header, ...argument];
    const weakInRequest = WEAK_SIGNALS.filter((regex) => values.some((text) => textHas(text, regex))).length;
    const weakInDescription = WEAK_WORDS.test(description);

    let confidence;
    if (level !== null && level <= NORMAL_MAX_LEVEL && weakInRequest === 0 && !weakInDescription) {
      confidence = 0.05; // 낮은 규칙 수준이고 같은 공격과 관련된 표기가 없는 정상 이벤트
    } else {
      // 애매한 경우: 수준 4~9 이거나 약한 신호가 있으면 alert 범위(0.5 이상 0.85 미만)에서 얼마나 닮았는지로 나눕니다.
      confidence = 0.5;
      confidence += Math.min(weakInRequest, 3) * 0.05;
      if (weakInDescription && !NEGATED.test(description)) confidence += 0.05;
      if (level !== null && level >= 7) confidence += 0.03;
      if (level !== null && level >= CLEAR_LEVEL) confidence += 0.07; // 수준은 높지만 완전한 구문이 없으면 block 하지 않고 alert 로 둡니다.
      if (count !== null && count >= REPEAT_COUNT) confidence += 0.03;
      confidence = Math.min(confidence, 0.8);
    }
    const final = clamp(confidence);
    if (final >= ALERT_AT) {
      // 가장 가까운 패턴 이름을 적습니다: 머리글 쪽 값에 약한 신호가 있으면 머리글 패턴, 아니면 주소 인자 패턴.
      const nearHeader = header.some((text) => WEAK_SIGNALS.some((regex) => textHas(text, regex)));
      const near = PATTERNS.find((pattern) => pattern.where === (nearHeader ? 'header' : 'argument') && !pattern.onlyWithLookup);
      return { action: 'alert', confidence: final, reason: `${near.name}과 일부만 맞습니다(완전한 구문 아님)` };
    }
    return { action: 'record', confidence: final, reason: '알려진 취약점 악용 형태와 맞는 패턴이 없는 정상 이벤트입니다' };
  } catch {
    // 어떤 입력에도 예외를 밖으로 내보내지 않습니다. 판단하지 못한 경보는 사람이 보도록 alert 로 둡니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '경보를 읽지 못해 사람이 확인하도록 알립니다' };
  }
}
