# AKFES 로컬 2클라이언트 테스트

Docker Desktop 오류를 우회할 수 있습니다. Python, Node.js와 npm이 설치된 Windows 노트북에서 실행하며 Arduino는 일반 채팅 테스트에 필요하지 않습니다.

## 실행

PowerShell에서 이 소스 폴더로 이동한 뒤 다음 한 줄을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\START_LOCAL_TEST_NO_DOCKER.ps1
```

스크립트는 긴 경로 오류를 피하도록 `%LOCALAPPDATA%\AKFES-LocalTest\venv`에 Python 환경을 만들고, SQLite·FastAPI·Vite를 직접 실행합니다. Redis 대신 개발 전용 메모리 rate limiter와 프로세스 내부 WebSocket 전달을 사용합니다. 운영 모드의 Redis fail-closed 정책은 변경하지 않습니다. 준비가 끝나면 같은 웹 주소를 사용하는 두 탭이 열립니다.

## 권장 테스트 순서

1. 첫 번째 탭에서 `회원가입 또는 중단된 가입 복구`를 누릅니다.
2. 사용자 이름을 `alice-test`로 입력하고 테스트용 비밀번호와 PowerShell에 표시된 초대 코드를 입력합니다.
3. 두 번째 탭에서는 `bob-test` 계정을 만듭니다.
4. Alice에서 정확한 사용자 이름 `bob-test`를 검색하고 대화를 요청합니다.
5. Bob에서 요청을 수락합니다.
6. 양쪽에서 일반 메시지를 보내 다음 항목을 확인합니다.
   - 송수신
   - 온라인 상태
   - 입력 중 표시
   - 전송됨·읽음 표시
   - 대화 전환 후 작성 중인 초안 복원
7. 메시지를 50개 넘게 보낸 뒤 대화 상단의 `이전 메시지 불러오기`를 확인합니다.
8. 브라우저 개발자 도구의 Network에서 새 메시지 여러 개가 와도 짧은 시간 안에 대화 전체 요청이 반복 폭주하지 않는지 확인합니다.

비밀 메시지, 비밀 파일과 Arduino PIN은 보드가 있을 때 별도로 테스트합니다.

## 종료

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\STOP_LOCAL_TEST_NO_DOCKER.ps1
```

종료 명령은 이 스크립트가 실행한 API와 웹 프로세스만 정지하고 테스트 계정, SQLite 데이터베이스와 암호화 파일은 보존합니다. 다음 실행 때 같은 초대 코드와 데이터를 계속 사용합니다.

생성된 초대 코드는 `.local-test\invite-code.txt`에도 저장됩니다. `.local-test` 폴더는 Git 검사 대상에서 제외됩니다.
