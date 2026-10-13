// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 규칙은 하나씩 추가합니다. RULE_IDS 에는 실제로 구현한 규칙만 적습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

// 규칙 device_registered: 엔진이 알려 준 deviceRegistered 가 정확히 true 일 때만 허용합니다.
// false 이거나 값이 없거나 true 가 아닌 다른 값이면 거부합니다.
export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
