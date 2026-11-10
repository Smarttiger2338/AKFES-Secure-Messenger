# 관리자 패널과 프로필 설정

관리자 패널은 `https://api.akfes.pe.kr/admin`에서 엽니다. 운영 설정의 `ADMIN_USERNAMES`에 포함된 승인 계정만 접근할 수 있으며 현재 기본 관리 아이디는 `admin`입니다.

최초 사용 시 관리자 계정으로 로그인하고 **관리 → 관리자 보안 → TOTP 설정 시작**을 누릅니다. 비밀번호를 다시 확인한 후 표시되는 비밀키를 인증 앱에 등록하고 6자리 코드를 확인합니다. 패스키는 TOTP 설정 후 추가할 수 있습니다. 계정 정지, 재활성화, 전체 장치 폐기는 작업마다 새로운 TOTP 또는 패스키 승인을 소비합니다.

관리자는 메시지 평문, 암호문, 파일 내용, E2EE 키를 조회할 수 없습니다.

## 이메일 인증 연결

비밀값은 `/opt/akfes/secrets/production.env`에 추가합니다.

```text
EMAIL_SMTP_PASSWORD=SMTP_PASSWORD
```

비밀이 아닌 값은 `/opt/akfes/app/deploy/vultr-production/.env.production`에 설정합니다.

```text
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=mailer@example.com
EMAIL_FROM=mailer@example.com
EMAIL_SMTP_STARTTLS=true
```

## 휴대전화 인증 연결

SMS 서비스 앞에 HTTPS 웹훅을 두고 다음 값을 설정합니다.

```text
SMS_WEBHOOK_URL=https://sms-gateway.example.com/send
SMS_WEBHOOK_BEARER=WEBHOOK_SECRET
```

AKFES는 웹훅에 `{"to":"+821012345678","message":"AKFES 인증 코드: 123456"}` 형식의 JSON을 전송합니다. 실제 SMS 업체 키는 브라우저나 AKFES 데이터베이스에 저장하지 않습니다.

설정 후 기존 `DEPLOY_AKFES_VULTR_V10.ps1`을 다시 실행하면 적용됩니다.
