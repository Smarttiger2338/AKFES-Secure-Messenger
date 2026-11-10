param(
    [string]$Server = 'api.akfes.kro.kr',
    [string]$User = 'akfesadmin',
    [string]$IdentityFile = (Join-Path $env:USERPROFILE '.ssh\akfes-vultr'),
    [switch]$DiagnosticsOnly,
    [ValidateRange(1, 20)]
    [int]$KeepReleaseCount = 3
)

$ErrorActionPreference = 'Stop'
$ExpectedFingerprint = 'SHA256:l0oaTHXCkFl93YjVVNr6bRaMJItUvKlbHGcz9lYnDqs'
$ExpectedArchiveHash = 'E450F4AC05667DAB32C736C2DE86CC2736206B91D0368F9F54A5EFB26FA430FD'
$Archive = Join-Path $PSScriptRoot 'AKFES-Server-Release.tar.gz'
$RemoteArchive = '/tmp/AKFES-Server-Release.tar.gz'

foreach ($command in @('ssh','scp','ssh-keyscan','ssh-keygen')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command is required." }
}
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw "Server archive is missing: $Archive" }
if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "Vultr SSH private key is missing: $IdentityFile" }
$actualHash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
if ($actualHash -ne $ExpectedArchiveHash) { throw "Archive SHA-256 mismatch. Expected $ExpectedArchiveHash, got $actualHash" }
$webIndex = Join-Path $PSScriptRoot 'server-source\web\index.html'
if (-not (Test-Path -LiteralPath $webIndex -PathType Leaf)) { throw "Web entry point is missing: $webIndex" }
$webIndexText = Get-Content -Raw -LiteralPath $webIndex
if ($webIndexText -notmatch 'src="(?<asset>/assets/index-[A-Za-z0-9_-]+\.js)"') {
    throw 'Web entry point does not reference a content-addressed JavaScript bundle.'
}
$ExpectedWebAsset = $Matches.asset

Write-Host 'Verifying the Vultr SSH ED25519 host key through the normal OpenSSH connection...'
$knownHosts = Join-Path ([IO.Path]::GetTempPath()) "akfes-vultr-known-hosts-$PID"
try {
    $defaultKnownHosts = Join-Path $env:USERPROFILE '.ssh\known_hosts'
    $sshDirectory = Split-Path -Parent $defaultKnownHosts
    if (-not (Test-Path -LiteralPath $sshDirectory -PathType Container)) { New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $defaultKnownHosts -PathType Leaf)) { New-Item -ItemType File -Path $defaultKnownHosts -Force | Out-Null }

    # This is intentionally the same connection form the operator already
    # uses manually. It avoids ssh-keyscan, which is blocked on some Windows
    # installations, and records a first-use key in normal known_hosts.
    $probeOptions = @('-i',$IdentityFile,'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=accept-new','-o','HostKeyAlgorithms=ssh-ed25519','-o','BatchMode=no','-o','ConnectTimeout=15')
    $target = "${User}@${Server}"
    Write-Host 'Connecting once to record the host key. Enter the SSH-key passphrase if prompted.' -ForegroundColor Yellow
    & ssh @probeOptions $target exit
    if ($LASTEXITCODE -ne 0) { throw "SSH host-key probe failed (exit $LASTEXITCODE). Verify that this exact command works: ssh -i `"$IdentityFile`" $target" }

    $hostRecords = @(& ssh-keygen.exe -F $Server -f $defaultKnownHosts 2>$null | Where-Object { $_ -and -not $_.StartsWith('#') })
    if ($hostRecords.Count -eq 0) { throw "OpenSSH connected but did not record a known_hosts entry for $Server." }
    [IO.File]::WriteAllLines($knownHosts, $hostRecords, [Text.UTF8Encoding]::new($false))
    $fingerprintLine = (& ssh-keygen.exe -lf $knownHosts -E sha256 2>$null | Where-Object { $_ -match [regex]::Escape($ExpectedFingerprint) } | Select-Object -First 1)
    if (-not $fingerprintLine) {
        $received = ((& ssh-keygen.exe -lf $knownHosts -E sha256 2>$null) | Select-Object -First 3) -join ' | '
        throw "Vultr SSH host fingerprint mismatch. Expected $ExpectedFingerprint. Received: $received"
    }
    Write-Host "SSH host fingerprint verified: $ExpectedFingerprint" -ForegroundColor Green

    $sshOptions = @('-i',$IdentityFile,'-o','IdentitiesOnly=yes','-o',"UserKnownHostsFile=$knownHosts",'-o','StrictHostKeyChecking=yes','-o','BatchMode=no','-o','NumberOfPasswordPrompts=1')
    $target = "${User}@${Server}"

    $diagnosticScript = @"
set +e
echo '===== AKFES CONTAINERS ====='
sudo docker ps -a --filter 'name=akfes-production-' --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' || true
echo '===== API CONTAINER STATE ====='
sudo docker inspect --format 'status={{.State.Status}} running={{.State.Running}} restarting={{.State.Restarting}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{json .State.Error}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}' akfes-production-api-1 2>&1 || true
echo '===== API HEALTH DETAILS ====='
sudo docker inspect --format '{{json .State.Health}}' akfes-production-api-1 2>&1 || true
echo '===== HOST PORT BINDINGS ====='
sudo docker inspect --format 'api={{json .HostConfig.PortBindings}}' akfes-production-api-1 2>&1 || true
sudo docker inspect --format 'auth={{json .HostConfig.PortBindings}}' akfes-production-auth-1 2>&1 || true
sudo ss -lntp 2>&1 | grep -E ':(18001|18003)[[:space:]]' || true
echo '===== ACTUAL API LOGS (LAST 300) ====='
sudo docker logs --tail=300 akfes-production-api-1 2>&1 || true
echo '===== ACTUAL AUTH LOGS (LAST 300) ====='
sudo docker inspect --format 'status={{.State.Status}} running={{.State.Running}} restarting={{.State.Restarting}} exit={{.State.ExitCode}} health={{json .State.Health}}' akfes-production-auth-1 2>&1 || true
sudo docker logs --tail=300 akfes-production-auth-1 2>&1 || true
echo '===== API HTTP LIVE / READY ====='
curl -sS -i --max-time 5 http://127.0.0.1:18001/health/live 2>&1 || true
curl -sS -i --max-time 5 http://127.0.0.1:18001/health/ready 2>&1 || true
echo '===== INTERNAL DNS ====='
sudo docker exec akfes-production-api-1 getent hosts db security-redis realtime-redis 2>&1 || true
echo '===== CADDY SERVICE STATE ====='
sudo systemctl status caddy --no-pager --full 2>&1 || true
sudo systemctl show caddy -p ActiveState -p SubState -p Result -p ExecMainStatus -p FragmentPath 2>&1 || true
echo '===== CADDY JOURNAL (LAST 200) ====='
sudo journalctl -u caddy --no-pager -n 200 2>&1 || true
echo '===== HTTP/HTTPS PORT OWNERS ====='
sudo ss -lntp 2>&1 | grep -E ':(80|443)[[:space:]]' || true
echo '===== ACTIVE CADDY CONFIG VALIDATION ====='
sudo caddy validate --config /etc/caddy/Caddyfile 2>&1 || true
echo '===== CADDY PATH PERMISSIONS ====='
sudo ls -ld /etc/caddy /etc/caddy/Caddyfile /var/log/caddy /var/lib/caddy 2>&1 || true
echo '===== STATIC WEB FILES AND PERMISSIONS ====='
sudo namei -l /var/www/akfes/index.html 2>&1 || true
sudo find /var/www/akfes -maxdepth 1 -type f -printf '%M %u:%g %s %p\n' 2>&1 || true
sudo -u caddy test -r /var/www/akfes/index.html && echo 'PASS: caddy can read index.html' || echo 'FAIL: caddy cannot read index.html'
echo '===== STATIC WEB BUNDLE DIAGNOSIS ====='
echo 'Application web entry:'
sudo sed -n '1,20p' /opt/akfes/app/web/index.html 2>&1 || true
echo 'Caddy web entry:'
sudo sed -n '1,20p' /var/www/akfes/index.html 2>&1 || true
echo 'Public web entry asset:'
curl -fsS --max-time 15 https://api.akfes.pe.kr/ 2>/dev/null | sed -n 's/.*src="\([^\"]*\.js\)".*/\1/p' || true
echo '===== SYSTEM SUMMARY ====='
date -Is 2>&1 || true
uname -a 2>&1 || true
uptime 2>&1 || true
free -h 2>&1 || true
df -hT / /opt/akfes /var/lib/docker 2>&1 || true
echo '===== AKFES DISK USAGE ====='
sudo du -sh /opt/akfes/app /opt/akfes/data /opt/akfes/backups /opt/akfes/releases /opt/akfes/secrets 2>&1 || true
echo '===== REMAINING DEPLOY UPLOADS ====='
sudo find /tmp -maxdepth 1 -type f -name 'AKFES-Vultr-Server-v*.tar.gz' -printf '%f %s bytes\n' 2>&1 || true
echo '===== ROLLBACK ARCHIVES ====='
sudo find /opt/akfes/backups -maxdepth 1 -type f -name 'app-before-*.tar.gz' -printf '%f %s bytes\n' 2>&1 || true
echo '===== DOCKER VERSION / STORAGE ====='
sudo docker version 2>&1 || true
sudo docker system df 2>&1 || true
sudo docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}' 2>&1 || true
echo '===== DATABASE LOGS (LAST 150) ====='
sudo docker logs --tail=150 akfes-production-db-1 2>&1 || true
echo '===== SECURITY REDIS LOGS (LAST 100) ====='
sudo docker logs --tail=100 akfes-production-security-redis-1 2>&1 || true
echo '===== REALTIME REDIS LOGS (LAST 100) ====='
sudo docker logs --tail=100 akfes-production-realtime-redis-1 2>&1 || true
echo '===== DOCKER SERVICE JOURNAL (LAST 100) ====='
sudo journalctl -u docker --no-pager -n 100 2>&1 || true
echo '===== ALL LISTENING TCP PORTS ====='
sudo ss -lntp 2>&1 || true
echo '===== FIREWALL STATUS ====='
sudo ufw status verbose 2>&1 || true
echo '===== FAIL2BAN SSH STATUS ====='
sudo fail2ban-client status sshd 2>&1 || true
echo '===== CADDY SYSTEMD UNIT ====='
sudo systemctl cat caddy --no-pager 2>&1 || true
echo '===== DOMAIN RESOLUTION ====='
getent ahosts api.akfes.pe.kr 2>&1 || true
echo '===== LOCAL HTTP HEADERS ====='
curl -sS -i --max-time 10 http://127.0.0.1:18001/health/ready 2>&1 || true
curl -sS -i --max-time 10 http://127.0.0.1:18003/health/ready 2>&1 || true
echo '===== PUBLIC HTTPS HEADERS ====='
curl -sS -i --max-time 15 https://api.akfes.pe.kr/health/ready 2>&1 || true
echo '===== PUBLIC WEB ROOT RESPONSE ====='
curl -sS -i --max-time 15 https://api.akfes.pe.kr/ 2>&1 | sed -n '1,40p' || true
echo '===== PUBLIC TLS CERTIFICATE ====='
openssl s_client -connect api.akfes.pe.kr:443 -servername api.akfes.pe.kr </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1 || true
exit 0
"@

    if ($DiagnosticsOnly) {
        Write-Host 'Collecting read-only Vultr API diagnostics. Enter the server sudo password if prompted.'
        & ssh -tt @sshOptions -- $target $diagnosticScript
        if ($LASTEXITCODE -ne 0) { throw 'Vultr API diagnostics failed.' }
        return
    }

    Write-Host 'Uploading the verified server-only archive...'
    Write-Host 'At the next prompt, enter the passphrase of the akfes-vultr SSH private key (not the server sudo password).' -ForegroundColor Yellow
    & scp @sshOptions -- $Archive "${target}:$RemoteArchive"
    if ($LASTEXITCODE -ne 0) { throw 'Server archive upload failed. The SSH private-key passphrase was incorrect, the key is not authorized, or SSH access is temporarily blocked.' }

$releaseName = 'v10-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $remoteScript = @"
set -euo pipefail
archive='$RemoteArchive'
trap 'sudo rm -f -- "`$archive"' EXIT
# Remove only superseded AKFES upload archives from /tmp. Never touch release,
# rollback-backup, database, file-storage, or secret directories.
for stale in /tmp/AKFES-Vultr-Server-v1.tar.gz /tmp/AKFES-Vultr-Server-v2.tar.gz /tmp/AKFES-Vultr-Server-v3.tar.gz /tmp/AKFES-Vultr-Server-v4.tar.gz /tmp/AKFES-Vultr-Server-v5.tar.gz /tmp/AKFES-Vultr-Server-v6.tar.gz /tmp/AKFES-Vultr-Server-v7.tar.gz /tmp/AKFES-Vultr-Server-v8.tar.gz /tmp/AKFES-Vultr-Server-v9.tar.gz /tmp/AKFES-Vultr-Server-v10.tar.gz; do
  if [ -L "`$stale" ]; then
    echo "Refusing to remove symlink: `$stale" >&2
    exit 1
  fi
  if [ -e "`$stale" ]; then
    [ -f "`$stale" ] || { echo "Refusing to remove non-file: `$stale" >&2; exit 1; }
    echo "Removing superseded upload: `$stale"
    sudo rm -f -- "`$stale"
  fi
done
release='/opt/akfes/releases/$releaseName'
test -f "`$archive"
sudo install -d -o root -g root -m 0755 "`$release"
# The archive is intentionally created with deploy/, server/, web/, etc. at
# its root.  Do not strip the first component: doing so turns web/index.html
# into index.html at the release root and silently leaves the old live web
# directory untouched.
sudo tar -xzf "`$archive" -C "`$release"
sudo install -d -o root -g root -m 0755 /opt/akfes/app /opt/akfes/backups
if sudo find /opt/akfes/app -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  sudo tar -C /opt/akfes/app -czf "/opt/akfes/backups/app-before-$releaseName.tar.gz" .
fi
# Generated web output must be replaced, not overlaid, or deleted hashed
# bundles remain publicly reachable. web-src was a legacy second client and is
# deliberately removed during migration.
for replaced in /opt/akfes/app/web /opt/akfes/app/web-src; do
  if [ -L "`$replaced" ]; then
    echo "Refusing to replace symlink: `$replaced" >&2
    exit 1
  fi
  if [ -e "`$replaced" ]; then sudo rm -rf -- "`$replaced"; fi
done
sudo cp -a "`$release"/. /opt/akfes/app/
cd /opt/akfes/app/deploy/vultr-production
sudo chmod 0755 ./*.sh
sudo ./first-install.sh
# A green API health check is not enough: it can succeed while Caddy still
# serves an older static web entry point. Verify both the release source and
# Caddy's actual web root before reporting deployment success.
grep -Fq '$ExpectedWebAsset' /opt/akfes/app/web/index.html
grep -Fq '$ExpectedWebAsset' /var/www/akfes/index.html
test -f "/var/www/akfes$ExpectedWebAsset"
# Release-history pruning runs as a separate maintenance operation after a
# confirmed deployment. It must never turn an otherwise healthy release into
# a failed deployment.
"@

    Write-Host 'Installing and validating AKFES on Vultr. Enter the server sudo password if prompted.'
    & ssh -tt @sshOptions -- $target $remoteScript
    $installExitCode = $LASTEXITCODE
    if ($installExitCode -ne 0) {
        Write-Host 'Installation failed; collecting API container diagnostics without changing server state.' -ForegroundColor Yellow
        & ssh -tt @sshOptions -- $target $diagnosticScript
        throw "Vultr installation or production verification failed (exit $installExitCode). API diagnostics are shown above."
    }
    Write-Host 'AKFES Vultr production API and web deployment passed.' -ForegroundColor Green
    Write-Host 'Web messenger: https://api.akfes.pe.kr/' -ForegroundColor Green
    Write-Host 'Registration invite: ssh to the server and run sudo akfes-invite'
} finally {
    if (Test-Path -LiteralPath $knownHosts) { Remove-Item -LiteralPath $knownHosts -Force }
}
