#!/usr/bin/env bash
# ShipSafe benchmark: generates a synthetic ~100k-line polyglot repository
# and measures wall-clock time and peak memory for a full scan.
#
#   scripts/benchmark.sh [lines] [shipsafe-binary]
#
# Requires semgrep, trivy, and gitleaks on PATH (run `shipsafe doctor`).
set -euo pipefail

LINES="${1:-100000}"
BIN="${2:-target/release/shipsafe}"

if [ ! -x "$BIN" ]; then
  echo "building release binary..."
  cargo build --release
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Generating synthetic repository (~${LINES} lines) in ${WORK_DIR} ..."
python3 - "$WORK_DIR" "$LINES" <<'PYEOF'
import os, sys

root, total_lines = sys.argv[1], int(sys.argv[2])

# Realistic mix: Python web handlers, JS modules, Go services.
py_tmpl = """def handler_{i}(request, cursor):
    user_id = request.args.get("id")
    name = sanitize(request.args.get("name"))
    cursor.execute("SELECT * FROM table_{i} WHERE id = %s", (user_id,))
    result = {{"id": user_id, "name": name, "index": {i}}}
    if result["id"] is None:
        raise ValueError("missing id for handler {i}")
    return result
"""

js_tmpl = """export function component{i}(props) {{
  const items = (props.items || []).map((x) => x * {i});
  const total = items.reduce((a, b) => a + b, 0);
  if (total < 0) {{
    throw new Error("negative total in component{i}");
  }}
  return {{ items, total, label: `component-{i}` }};
}}
"""

go_tmpl = """func Service{i}(ctx context.Context, id string) (string, error) {{
\tif id == "" {{
\t\treturn "", fmt.Errorf("service{i}: empty id")
\t}}
\tresult := process{i}(id)
\treturn result, nil
}}

func process{i}(id string) string {{
\treturn id + "-{i}"
}}
"""

lines_written = 0
i = 0
os.makedirs(f"{root}/src/py", exist_ok=True)
os.makedirs(f"{root}/src/js", exist_ok=True)
os.makedirs(f"{root}/src/go", exist_ok=True)

py = open(f"{root}/src/py/handlers_0.py", "w")
js = open(f"{root}/src/js/components_0.js", "w")
go = open(f"{root}/src/go/services_0.go", "w")
go.write("package services\n\nimport (\n\t\"context\"\n\t\"fmt\"\n)\n\n")

while lines_written < total_lines:
    if i % 200 == 0 and i > 0:
        for f in (py, js, go):
            f.close()
        n = i // 200
        py = open(f"{root}/src/py/handlers_{n}.py", "w")
        js = open(f"{root}/src/js/components_{n}.js", "w")
        go = open(f"{root}/src/go/services_{n}.go", "w")
        go.write("package services\n\nimport (\n\t\"context\"\n\t\"fmt\"\n)\n\n")
    py.write(py_tmpl.format(i=i))
    js.write(js_tmpl.format(i=i))
    go.write(go_tmpl.format(i=i))
    lines_written += 30
    i += 1

for f in (py, js, go):
    f.close()

# Dependency manifests so SCA has something to scan.
with open(f"{root}/requirements.txt", "w") as f:
    f.write("requests==2.31.0\nflask==3.0.0\npyyaml==6.0.1\n")

print(f"generated ~{lines_written} lines across {i} units")
PYEOF

ACTUAL_LINES=$(find "$WORK_DIR/src" -type f | xargs wc -l | tail -1 | awk '{print $1}')
echo "Actual lines: ${ACTUAL_LINES}"
echo

TIME_CMD="/usr/bin/time -l"   # macOS: -l prints peak RSS
if ! /usr/bin/time -l true 2>/dev/null; then
  TIME_CMD="/usr/bin/time -v" # GNU time
fi

echo "Running: $BIN scan -p $WORK_DIR (sast,sca,secrets)"
START=$(date +%s)
$TIME_CMD "$BIN" scan -p "$WORK_DIR" --fail-on critical 2>&1 \
  | grep -E "real|maximum resident|Maximum resident|Elapsed|検出|findings" || true
END=$(date +%s)
echo
echo "Total wall-clock: $((END - START))s for ${ACTUAL_LINES} lines"
