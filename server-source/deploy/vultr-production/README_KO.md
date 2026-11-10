# AKFES Vultr 운영 배포

이 구성은 최근 준비한 Vultr 서버 한 대를 전용 운영 서버로 사용합니다.

- 도메인: `api.akfes.pe.kr`
- 공인 IPv4: `158.247.253.60`
- 설치 위치: `/opt/akfes/app`
- 영구 데이터: `/opt/akfes/data`
- 운영 비밀값: `/opt/akfes/secrets`
- 백업: `/opt/akfes/backups`
- 외부 공개: Caddy의 `80/443`만
- API: 호스트 루프백 `127.0.0.1:18001`
- 인증/Arduino: 호스트 루프백 `127.0.0.1:18003`
- PostgreSQL과 두 Redis는 Docker 내부 네트워크에서만 접근 가능

## 최초 설치

서버 패키지를 `/opt/akfes/app`에 업로드한 후 실행합니다.

```bash
cd /opt/akfes/app/deploy/vultr-production
chmod +x *.sh
sudo ./first-install.sh
```

초대 코드는 서버의 `/opt/akfes/secrets/registration-invite.txt`에만 저장됩니다. 클라이언트 패키지에 포함하면 안 됩니다.

## 이후 서버 업데이트

새 서버 패키지를 별도 릴리스 경로에 풀고 `/opt/akfes/app`의 코드만 갱신합니다. `/opt/akfes/data`와 `/opt/akfes/secrets`는 교체하거나 삭제하지 않습니다. 코드 갱신 후 `sudo ./update-server.sh`를 실행하면 먼저 백업하고 기존 데이터와 비밀값을 유지한 채 이미지를 재빌드합니다.

## 클라이언트 독립 업데이트

클라이언트는 `https://api.akfes.pe.kr` 및 `wss://api.akfes.pe.kr`에 고정됩니다. 클라이언트 업데이트는 서버 컨테이너나 데이터베이스를 재설치하지 않습니다.
