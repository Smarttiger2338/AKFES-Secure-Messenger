#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
AKFES 서버 관리 명령

  akfes-help
      이 도움말을 표시합니다.

  sudo akfes-invite
      현재 회원가입 초대 코드를 표시합니다.

  sudo akfes-clean-test-data --preview
      삭제 대상만 확인합니다. 데이터는 변경하지 않습니다.

  sudo env AKFES_CONFIRM_DELETE_ALL_TEST_DATA=DELETE-ALL-AKFES-TEST-DATA akfes-clean-test-data --execute
      모든 테스트 계정·장치·대화·암호화 파일을 백업한 뒤 삭제합니다.
      실제 사용자 데이터가 있으면 실행하면 안 됩니다.

  sudo systemctl status akfes-backup.timer
      매일 실행되는 백업 예약 상태를 확인합니다.

  sudo /opt/akfes/app/deploy/vultr-production/verify-production.sh
      API, HTTPS, Caddy, 포트 격리 상태를 검증합니다.

웹 주소: https://api.akfes.pe.kr/
EOF
