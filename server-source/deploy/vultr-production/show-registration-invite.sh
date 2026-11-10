#!/usr/bin/env bash
set -euo pipefail

INVITE_FILE=/opt/akfes/secrets/registration-invite.txt

if [[ "${EUID}" -ne 0 ]]; then
  echo '관리자 권한이 필요합니다. 다음 명령을 사용하세요: sudo akfes-invite' >&2
  exit 1
fi
if [[ -L "$INVITE_FILE" ]]; then
  echo "Refusing to read a symlink: $INVITE_FILE" >&2
  exit 1
fi
if [[ ! -f "$INVITE_FILE" || ! -s "$INVITE_FILE" ]]; then
  echo "Registration invite is missing or empty: $INVITE_FILE" >&2
  exit 1
fi

echo 'AKFES registration invite:'
cat -- "$INVITE_FILE"
echo
echo '이 값은 비밀번호처럼 취급하고 공개 채팅이나 로그에 남기지 마세요.'
