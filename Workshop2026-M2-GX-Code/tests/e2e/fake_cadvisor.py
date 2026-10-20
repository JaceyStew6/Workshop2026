"""Exporteur compatible cAdvisor pour les tests NATIFS (sans Docker).

Expose, pour le processus de payment-api, les deux métriques que le contrat de features.py attend :
  container_cpu_usage_seconds_total{name="payment-api"}
  container_memory_working_set_bytes{name="payment-api"}
Le PID est relu à chaque scrape (le processus change quand la remédiation le redémarre).
Usage : python fake_cadvisor.py --pidfile /tmp/ra-run/pids/payment --port 18110
"""
import argparse
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import psutil

ap = argparse.ArgumentParser()
ap.add_argument("--pidfile", required=True)
ap.add_argument("--port", type=int, default=18110)
ap.add_argument("--name", default="payment-api")
args = ap.parse_args()
_cpu_offset = 0.0
_last_pid, _last_cpu = None, 0.0


def snapshot():
    global _cpu_offset, _last_pid, _last_cpu
    try:
        pid = int(open(args.pidfile).read().strip())
        p = psutil.Process(pid)
        t = p.cpu_times()
        cpu = t.user + t.system + sum(c.cpu_times().user + c.cpu_times().system for c in p.children(recursive=True))
        mem = p.memory_info().rss
    except (OSError, ValueError, psutil.Error):
        return None
    if _last_pid is not None and pid != _last_pid:      # redémarrage : le compteur cumulatif continue de croître
        _cpu_offset += _last_cpu
    _last_pid, _last_cpu = pid, cpu
    return cpu + _cpu_offset, mem


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        s = snapshot()
        lines = []
        if s:
            lines += ["# TYPE container_cpu_usage_seconds_total counter",
                      f'container_cpu_usage_seconds_total{{name="{args.name}"}} {s[0]}',
                      "# TYPE container_memory_working_set_bytes gauge",
                      f'container_memory_working_set_bytes{{name="{args.name}"}} {s[1]}']
        body = ("\n".join(lines) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("127.0.0.1", args.port), H).serve_forever()
