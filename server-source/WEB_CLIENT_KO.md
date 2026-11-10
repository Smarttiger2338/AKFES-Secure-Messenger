# AKFES 웹 클라이언트

웹 주소: `https://api.akfes.pe.kr/`

- 브라우저는 Windows 앱과 별개의 E2EE 장치입니다.
- 개인키, PreKey, Ratchet 상태는 계정 비밀번호에서 파생한 키로 암호화되어 IndexedDB에 저장됩니다.
- 접근 토큰은 메모리에만 유지되며 새로고침 또는 탭 종료 시 사라집니다.
- 새 웹 장치는 승인된 Windows 앱의 장치 관리 화면에서 Arduino 승인을 받아야 합니다.
- 첫 계정 생성과 첫 장치 승인은 Windows 앱에서만 할 수 있습니다.
- 웹에서는 로그인, 사용자 검색, 대화, E2EE v4 메시지 송수신, Safety Number 검증을 지원합니다.
- Arduino 검색·펌웨어·장치 승인·폐기는 Windows 앱에만 남겨 둡니다.

서버 배포가 끝난 뒤 `/`, `/health/ready`, `/api/*`, `/ws`가 각각 웹·상태·API·WebSocket으로 라우팅됩니다.
