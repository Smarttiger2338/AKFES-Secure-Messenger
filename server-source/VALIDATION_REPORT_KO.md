# AKFES Vultr 서버 전용 배포본 검증

## 적용 대상

- Vultr `158.247.253.60`
- `api.akfes.pe.kr`
- Ubuntu + Docker Compose + Caddy
- `/opt/akfes` 운영 디렉터리

## 통과한 검사

- Python 서버 소스 `compileall`: PASS
- 기존 보안 정적 감사: PASS
- 기존 릴리스 후보 감사: PASS
- 서버 전용 패키지 필수 파일 검사: PASS
- 클라이언트 및 로컬 테스트 스택 제외 검사: PASS
- 운영 비밀값·초대 코드·JWT 개인키 미포함 검사: PASS
- PostgreSQL/Redis 호스트 포트 미공개 검사: PASS
- API/Auth 루프백 바인딩 검사: PASS
- Docker 내부 네트워크 검사: PASS
- Caddy API/Auth 분기 검사: PASS
- `api.akfes.pe.kr` 운영 주소 고정 검사: PASS

## 서버에서 수행해야 하는 검사

이 Windows 작업 환경에서는 Docker CLI/daemon과 서버용 Python 테스트 의존성을 사용할 수 없어 다음 검사는 Vultr의 `deploy.sh` 및 `verify-production.sh`가 수행합니다.

- `docker compose config --quiet`
- 이미지 pull/build
- PostgreSQL, Security Redis, Realtime Redis, API, Auth 실제 기동
- `/health/live`, `/health/ready`
- 외부 HTTPS `https://api.akfes.pe.kr/health/ready`
- 내부 포트 외부 노출 검사

서버 검사가 하나라도 실패하면 운영 배포 완료로 간주하지 않습니다.
