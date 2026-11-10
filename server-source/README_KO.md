# AKFES Vultr 서버 + 웹 클라이언트 배포본 v10

이 압축본은 `api.akfes.pe.kr`의 Vultr 운영 서버와 같은 주소에서 제공되는 E2EE 웹 클라이언트를 함께 배포합니다. Windows 실행 파일은 포함하지 않습니다.

1. 이 폴더의 내용을 Vultr의 `/opt/akfes/app`에 업로드합니다.
2. 최초 설치는 `/opt/akfes/app/deploy/vultr-production/first-install.sh`를 `sudo`로 실행합니다.
3. `/opt/akfes/data`와 `/opt/akfes/secrets`는 다음 서버 코드 업데이트 때 덮어쓰거나 삭제하지 않습니다.

공개 포트는 Caddy의 80/443뿐입니다. PostgreSQL, Redis, API 내부 포트는 외부에 공개하지 않습니다.

v10은 중단된 가입 복구, Arduino PIN 인증, Windows/웹 동일 UI, 장치 간 E2EE 대화 동기화를 포함합니다. 배포 스크립트는 SSH ED25519 지문과 압축본 SHA-256을 검증한 뒤 업로드·설치·API/웹 검증을 수행해야 합니다.

배포 후 초대 코드는 서버에서 `sudo akfes-invite` 한 줄로 확인할 수 있습니다. 명령은 `/opt/akfes/secrets/registration-invite.txt`의 일반 파일만 읽으며 관리자 권한 없이는 실행되지 않습니다.

최신 Windows v25 키패드 펌웨어는 PIN을 Arduino의 4×3/4×4 키패드에서 직접 두 번 등록합니다. 서버는 PIN 평문 대신 장치별 파생 검증 키만 암호화해 보관합니다. 직전 v25 클라이언트가 새 설치 파일로 전환되는 동안에는 기존 PIN 요청 형식도 호환 처리합니다.

최초 등록 장치가 승인 대기 중이고 계정에 승인된 장치가 전혀 없을 때 `/api/arduino/bootstrap-provisioning`이 해당 장치 전용 Arduino 키를 제공합니다. 이미 다른 신뢰 장치에서 승인받은 추가 Windows 장치도 자기 Arduino를 최초 1회 등록할 수 있습니다. PIN 변경은 현재 키패드 PIN 인증을 먼저 통과한 뒤 별도 변경 절차로만 수행합니다.

웹 주소는 `https://api.akfes.pe.kr/`입니다. 웹 브라우저는 독립 E2EE 장치로 등록되며 장치 승인·폐기는 Arduino가 연결된 Windows 앱에서 처리합니다.
