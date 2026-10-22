#!/bin/sh
# Pile NATIVE (sans Docker) pour tests de bout en bout dans un environnement qui n'a pas Docker.
# Usage : RUN=/tmp/ra-run sh tests/e2e/stack.sh start|stop|status [service...]
# Ports : auth 18001, payment 18002, waf public/interne/admin 18080/18081/18082, remediation 18000,
#         prometheus 19090, exporter cAdvisor-compatible 18110.
set -eu
RUN="${RUN:-/tmp/ra-run}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
S="$RUN/.secrets"
mkdir -p "$RUN/pids" "$RUN/logs"

start_one() {  # nom, répertoire, commande... (variables d'environnement héritées)
  name="$1"; dir="$2"; shift 2
  if [ -f "$RUN/pids/$name" ] && kill -0 "$(cat "$RUN/pids/$name")" 2>/dev/null; then echo "$name déjà démarré"; return; fi
  ( cd "$dir" && nohup "$@" > "$RUN/logs/$name.log" 2>&1 & echo $! > "$RUN/pids/$name" )
  echo "$name démarré (pid $(cat "$RUN/pids/$name"))"
}

svc_auth()    { DB_HOST=127.0.0.1 DB_PASSWORD_FILE=$S/db_password JWT_SECRET_FILE=$S/jwt_secret \
                DEMO_PASSWORD_FILE=$S/demo_password BOT_PASSWORD_FILE=$S/bot_password PROBE_PASSWORD_FILE=$S/probe_password \
                start_one auth "$HERE/services/auth-service" python3 -m uvicorn app:app --port 18001 --no-access-log; }
svc_payment() { DB_HOST=127.0.0.1 DB_PASSWORD_FILE=$S/db_password JWT_SECRET_FILE=$S/jwt_secret \
                RISK_COST_ITER="${RISK_COST_ITER:-30000}" \
                start_one payment "$HERE/services/payment-api" python3 -m uvicorn app:app --port 18002 --no-access-log; }
svc_waf()     { AUTH_URL=http://127.0.0.1:18001 PAYMENT_URL=http://127.0.0.1:18002 FRONTEND_URL=http://127.0.0.1:18999 \
                WAF_PUBLIC_PORT=18080 WAF_INTERNAL_PORT=18081 WAF_ADMIN_PORT=18082 BIND=0.0.0.0 \
                WAF_ADMIN_TOKEN_FILE=$S/waf_admin_token BAN_FILE=$RUN/bans.json NEVER_BAN="${NEVER_BAN:-192.168.137.1}" \
                start_one waf "$HERE/services/waf" python3 main.py; }

svc_cadvisor() { start_one cadvisor "$HERE/tests/e2e" python3 fake_cadvisor.py --pidfile "$RUN/pids/payment" --port 18110; }
svc_prom()     { start_one prom "$RUN" "$RUN/bin/prometheus" --config.file="$HERE/tests/e2e/prometheus.native.yml" \
                 --storage.tsdb.path="$RUN/promdata" --storage.tsdb.retention.time=6h --web.listen-address=127.0.0.1:19090; }
svc_remediation() { RUN=$RUN start_one remediation "$HERE/tests/e2e" python3 run_remediation.py; }
svc_detector() { PROMETHEUS_URL=http://127.0.0.1:19090 REMEDIATION_URL=http://127.0.0.1:18000 \
                 MODEL_PATH="${MODEL_PATH:-$RUN/model.joblib}" REMEDIATION_TOKEN_FILE=$S/remediation_token TICK_SECONDS=5 \
                 start_one detector "$HERE/services/ml-detector" python3 detector.py; }

stop_one() { [ -f "$RUN/pids/$1" ] && { kill "$(cat "$RUN/pids/$1")" 2>/dev/null || true; rm -f "$RUN/pids/$1"; echo "$1 arrêté"; } || true; }

cmd="${1:-status}"; shift || true
ALL="${*:-auth payment waf cadvisor prom remediation}"
case "$cmd" in
  start)  for s in $ALL; do "svc_$s"; done; sleep 3 ;;
  stop)   for s in $ALL; do stop_one "$s"; done ;;
  status) for f in "$RUN"/pids/*; do [ -f "$f" ] || continue; n=$(basename "$f"); kill -0 "$(cat "$f")" 2>/dev/null && echo "$n: up" || echo "$n: down"; done ;;
esac
