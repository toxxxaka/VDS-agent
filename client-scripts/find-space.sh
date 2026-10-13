#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
usage() { echo "Usage: $0 [--top N] [--min-size SIZE]  (SIZE: bytes or K/M/G/T)"; }
top=20; min_size=100M
while (($#)); do
  case "$1" in
    --top) (($# >= 2)) || { usage >&2; exit 2; }; top=$2; shift 2 ;;
    --min-size) (($# >= 2)) || { usage >&2; exit 2; }; min_size=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $top =~ ^[0-9]+$ ]] && (( top >= 1 && top <= 100 )) || { echo "--top must be 1..100" >&2; exit 2; }
[[ $min_size =~ ^[0-9]+[KkMmGgTt]?$ ]] || { echo "Invalid --min-size" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 - "$top" "$min_size" <<'PY'
import os
import heapq
import re
import sys
import time

top = int(sys.argv[1])
raw = sys.argv[2].upper()
amount, unit = re.fullmatch(r"([0-9]+)([KMGT]?)", raw).groups()
minimum = int(amount) * 1024 ** ("KMGT".index(unit) + 1 if unit else 0)
base_device = os.stat("/").st_dev
roots = {
    "/var/log": 4, "/var/cache": 4, "/var/backups": 4,
    "/tmp": 3, "/var/tmp": 3, "/home": 6,
    "/home/bitrix": 7, "/home/bitrix/www": 7,
    "/var/www": 7, "/var/www/html": 7,
    "/opt": 5, "/usr/local/mgr5": 5, "/var/lib/docker": 5,
    "/var/lib/mysql": 1,
}
for home in os.scandir("/home"):
    if home.is_dir(follow_symlinks=False):
        for suffix in ("www", "web", "public_html"):
            roots[os.path.join(home.path, suffix)] = 7
names = {"log", "logs", "cache", "caches", "tmp", "temp", "backup",
         "backups", "managed_cache", "stack_cache", "upload"}
seen = set()
candidates = []
skipped_mounts = set()
def walk(root, depth):
    if not os.path.isdir(root) or os.path.islink(root):
        return
    if os.stat(root).st_dev != base_device:
        skipped_mounts.add(root)
        return
    for current, dirs, files in os.walk(root, followlinks=False):
        level = os.path.relpath(current, root).count(os.sep) + (current != root)
        dirs[:] = [d for d in dirs
                   if level < depth
                   and not os.path.islink(os.path.join(current, d))
                   and os.stat(os.path.join(current, d)).st_dev == base_device
                   and not (root == "/var/lib/docker" and d == "overlay2")]
        if current in seen:
            continue
        seen.add(current)
        parent = os.path.basename(os.path.dirname(current)).lower()
        name = os.path.basename(current).lower()
        if name in names or (parent == "bitrix" and name in names):
            candidates.append(current)
        if current in ("/var/lib/docker/containers", "/var/lib/mysql"):
            candidates.append(current)

for root, depth in roots.items():
    try:
        walk(root, depth)
    except (OSError, PermissionError) as exc:
        print(f"Skipped {root}: {exc}", file=sys.stderr)

def human(n):
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024

def inspect(path):
    total = count = oldest = 0
    largest = (0, "")
    files_found = []
    for current, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current, d))
                   and os.stat(os.path.join(current, d)).st_dev == base_device
                   and not (current == "/var/lib/docker" and d == "overlay2")]
        for filename in files:
            item = os.path.join(current, filename)
            try:
                info = os.stat(item, follow_symlinks=False)
            except OSError:
                continue
            if not __import__("stat").S_ISREG(info.st_mode) or info.st_dev != base_device:
                continue
            if path == "/var/lib/docker/containers" and not filename.endswith("-json.log"):
                continue
            if path == "/var/lib/mysql" and not filename.endswith((".log", ".err")):
                continue
            total += info.st_blocks * 512
            count += 1
            oldest = min(oldest, info.st_mtime) if oldest else info.st_mtime
            if info.st_size > largest[0]:
                largest = (info.st_size, item)
            if len(files_found) < top:
                heapq.heappush(files_found, (info.st_size, item))
            elif (info.st_size, item) > files_found[0]:
                heapq.heapreplace(files_found, (info.st_size, item))
    return total, count, oldest, largest, files_found

rows = []
large_files = {}
for path in dict.fromkeys(candidates):
    try:
        size, count, oldest, largest, files = inspect(path)
    except (OSError, PermissionError) as exc:
        print(f"Skipped {path}: {exc}", file=sys.stderr)
        continue
    for fsize, item in files:
        large_files[item] = fsize
    if size < minimum:
        continue
    rows.append((size, path, count, oldest, largest[0]))
rows.sort(reverse=True)
now = time.time()
print(f"Каталоги логов/кэша/бэкапов: {len(rows)} ≥ {human(minimum)}; показаны TOP-{top}")
print("Размер | Файлов | Самый старый файл | Макс. файл | Путь")
for size, path, count, oldest, largest in rows[:top]:
    age = f"{int((now-oldest)//86400)} дн." if oldest else "—"
    print(f"{human(size):>8} | {count:>7} | {age:>17} | {human(largest):>10} | {path}")
print(f"\nTOP-{top} самых больших файлов в найденных каталогах:")
for size, path in sorted(((s, p) for p, s in large_files.items()), reverse=True)[:top]:
    print(f"{human(size):>8}  {path}")
print("\nПримечание: overlay2 не считается кэшем и не сканируется. Данные не удалялись.")
if skipped_mounts:
    print(f"Пропущено отдельных файловых систем: {len(skipped_mounts)}")
PY
