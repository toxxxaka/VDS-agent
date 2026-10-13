#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
usage() { echo "Usage: $0 [--full]"; }
full=0
case ${1:-} in
  '') ;;
  --full) full=1 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
(($# <= 1)) || { usage >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
for cmd in journalctl systemctl systemd-analyze last awk; do
  command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }
done
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  red=$'\033[31m'; yellow=$'\033[33m'; green=$'\033[32m'; bold=$'\033[1m'; reset=$'\033[0m'
else red=''; yellow=''; green=''; bold=''; reset=''; fi
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
limit=25; lines=1800
if ((full)); then limit=30; lines=8000; fi
critical='kernel panic|oops:|segfault|out of memory|oom-kill|killed process|i/o error|input/output error|ext4.*error|xfs.*error|nvme.*error|scsi.*error|read-only file system|remount.*read-only|watchdog|soft lockup|hard lockup|blocked for more than|hung task|emergency mode|rescue mode|dependency failed|failed to mount|filesystem.*error'
warning='failed|failure|timed out|timeout|dhcp.*(fail|error|timeout)|network.*(fail|error)|interface.*(fail|error)|route.*(fail|error)|systemd-networkd.*(fail|error)|networkmanager.*(fail|error)|virtio.*(fail|error)|qemu.*(fail|error)|kvm.*(fail|error)|hypervisor.*(fail|error)|snapshot.*(fail|error)|backup.*(fail|error)|docker.*(fail|error)|containerd.*(fail|error)|fsck.*(fail|error)|mount.*(fail|error)'
for boot in 0 -1 -2; do
  if journalctl -b "$boot" -p 0..4 --no-pager -o short-iso -n "$lines" >"$tmp/boot$boot" 2>"$tmp/error$boot"; then
    :
  else
    : >"$tmp/boot$boot"
  fi
done
section() { printf '\n%s%s%s\n' "$bold" "$1" "$reset"; }
show_matches() {
  local file=$1 pattern=$2 max=$3
  if [[ ! -s $file ]]; then echo "(journal unavailable)"; return; fi
  awk -v p="$pattern" -v max="$max" '
    BEGIN { IGNORECASE=1; count=0 }
    {
      line=tolower($0)
      if (line !~ p) next
      key=$0
      sub(/^[^ ]+ [^ ]+ /, "", key)
      gsub(/[0-9]+/, "#", key)
      if (seen[key]++) next
      print
      count++
      if (count >= max) exit
    }
    END { if (count==0) print "(none)" }
  ' "$file"
}
section "1. Краткий статус системы"
printf 'Хост: %s | Сейчас: %s | Uptime: %s\n' "$(hostname)" "$(date -u '+%F %T UTC')" "$(uptime -p)"
printf 'Сбойные units: '
failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF {n++} END {print n+0}')
echo "$failed"
systemctl --failed --no-pager --no-legend 2>/dev/null | awk 'NR<=10 {print}' || true
section "2. Критические ошибки"
show_matches "$tmp/boot0" "$critical" "$limit"
section "3. Предупреждения"
show_matches "$tmp/boot0" "$warning" "$limit"
section "4. TOP-10 медленных служб"
systemd-analyze blame --no-pager 2>/dev/null | awk 'NR<=10 {print}' || echo "(unavailable)"
echo "Critical chain:"
if ((full)); then chain_limit=20; else chain_limit=10; fi
systemd-analyze critical-chain --no-pager 2>/dev/null | awk -v max="$chain_limit" 'NR<=max {print}' || true
section "5. Ошибки текущей загрузки"
show_matches "$tmp/boot0" "$critical|$warning" "$limit"
for boot in -1 -2; do
  section "6. Ошибки загрузки $boot"
  show_matches "$tmp/boot$boot" "$critical|$warning" "$limit"
done
section "7. Последние reboot/shutdown/crash"
last -x -n 20 reboot shutdown >"$tmp/last" 2>/dev/null || true
awk 'NR<=20 {print}' "$tmp/last"
section "8. Короткий итог"
if grep -Eiq 'out of memory|oom-kill|killed process' "$tmp/boot0"; then
  printf '%sВероятная причина: нехватка памяти или OOM killer.%s\n' "$red" "$reset"
elif grep -Eiq 'i/o error|input/output error|ext4.*error|xfs.*error|nvme.*error|scsi.*error|read-only file system|filesystem.*error' "$tmp/boot0"; then
  printf '%sВероятная причина: файловая система или накопитель; проверьте диск.%s\n' "$red" "$reset"
elif grep -Eiq 'crash' "$tmp/last"; then
  printf '%sВ истории загрузок есть признаки аварийного завершения; проверьте предыдущий boot.%s\n' "$red" "$reset"
elif grep -Eiq 'dhcp.*(fail|error)|network.*(fail|error)|route.*(fail|error)' "$tmp/boot0"; then
  printf '%sВозможная причина: ошибка сетевой настройки.%s\n' "$yellow" "$reset"
elif grep -Eiq "$critical" "$tmp/boot0"; then
  printf '%sОбнаружены критические события; вероятную причину уточните по строкам выше.%s\n' "$red" "$reset"
elif ((failed > 0)); then
  printf '%sЕсть сбойные systemd units; проверьте их журналы.%s\n' "$yellow" "$reset"
elif grep -Eiq "$warning" "$tmp/boot0"; then
  printf '%sЕсть предупреждения; вероятную причину уточните по строкам выше.%s\n' "$yellow" "$reset"
else
  printf '%sВ просмотренных записях явных критических проблем нет.%s\n' "$green" "$reset"
fi

if ((full)); then
  section "Дополнительно: расширенный journal (последние $limit строк каждого boot)"
  for boot in 0 -1 -2; do
    echo "boot $boot:"
    tail -n 100 "$tmp/boot$boot"
  done
fi
echo "Проверено до $lines записей уровня warning и выше на каждую загрузку; вывод ограничен."
