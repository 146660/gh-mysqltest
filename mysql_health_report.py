#!/usr/bin/env python3
"""MySQL 8.4 health check -> single easy-to-read HTML report.

Usage:
    python mysql_health_report.py                 # uses servers.json
    python mysql_health_report.py -c other.json --open

Passwords are NEVER stored. For each server they are read from environment
variables (MYSQL_PWD_<NAME>, SSH_PWD_<NAME>) or prompted at run time, which
suits BeyondTrust-rotated credentials (just paste the current one).
"""
import argparse
import datetime as dt
import getpass
import html
import json
import os
import re
import sys
import webbrowser

import mysql.connector

OK, WARN, CRIT, INFO = "OK", "WARN", "CRIT", "INFO"
RANK = {OK: 0, INFO: 0, WARN: 1, CRIT: 2}


# ---------------------------------------------------------------- helpers
def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def fmt_dur(sec):
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m"


def level(value, warn, crit, higher_is_bad=True):
    if higher_is_bad:
        return CRIT if value >= crit else WARN if value >= warn else OK
    return CRIT if value <= crit else WARN if value <= warn else OK


def env_key(name):
    return re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def get_secret(env_var, prompt):
    return os.environ.get(env_var) or getpass.getpass(prompt)


# ---------------------------------------------------------------- collection
def rows(cur, sql):
    cur.execute(sql)
    return cur.fetchall()


def collect(conn):
    cur = conn.cursor(dictionary=True)
    st = {r["Variable_name"]: r["Value"] for r in rows(cur, "SHOW GLOBAL STATUS")}
    var = {r["Variable_name"]: r["Value"] for r in rows(cur, "SHOW GLOBAL VARIABLES")}
    f = lambda d, k: float(d.get(k, 0) or 0)

    checks = []  # (category, check, value, status, note)

    def add(cat, name, value, status=INFO, note=""):
        checks.append((cat, name, value, status, note))

    # --- General
    uptime = f(st, "Uptime")
    add("General", "Version", f"{var.get('version')} ({var.get('version_comment')})")
    add("General", "Uptime", fmt_dur(uptime),
        WARN if uptime < 3600 else OK, "Restarted within the last hour" if uptime < 3600 else "")
    add("General", "read_only", var.get("read_only"), INFO,
        "super_read_only=" + str(var.get("super_read_only")))
    add("General", "Binary logging", var.get("log_bin"), INFO)

    # --- Connections
    max_conn = f(var, "max_connections")
    cur_conn = f(st, "Threads_connected")
    pct = cur_conn / max_conn * 100 if max_conn else 0
    add("Connections", "Connections in use", f"{int(cur_conn)} / {int(max_conn)} ({pct:.0f}%)",
        level(pct, 70, 85))
    peak = f(st, "Max_used_connections")
    add("Connections", "Peak connections", f"{int(peak)} ({peak / max_conn * 100:.0f}% of max)",
        level(peak / max_conn * 100, 80, 95) if max_conn else INFO)
    running = f(st, "Threads_running")
    add("Connections", "Threads running", int(running), level(running, 20, 50))
    add("Connections", "Aborted connects (since start)", int(f(st, "Aborted_connects")),
        WARN if f(st, "Aborted_connects") > 100 else OK, "Failed logins / handshakes")
    add("Connections", "Rejected: max_connections reached",
        int(f(st, "Connection_errors_max_connections")),
        CRIT if f(st, "Connection_errors_max_connections") > 0 else OK)

    # --- Performance
    qps = f(st, "Questions") / uptime if uptime else 0
    add("Performance", "Avg queries/sec since start", f"{qps:,.1f}")
    add("Performance", "Slow queries (since start)", int(f(st, "Slow_queries")), INFO,
        f"long_query_time={var.get('long_query_time')}s, slow_query_log={var.get('slow_query_log')}")
    tmp_t, tmp_d = f(st, "Created_tmp_tables"), f(st, "Created_tmp_disk_tables")
    ratio = tmp_d / tmp_t * 100 if tmp_t else 0
    add("Performance", "Temp tables created on disk", f"{ratio:.1f}%", level(ratio, 25, 50))
    waits = f(st, "Innodb_row_lock_current_waits")
    add("Performance", "InnoDB row-lock waits now", int(waits), WARN if waits > 0 else OK)

    # --- InnoDB
    reqs, miss = f(st, "Innodb_buffer_pool_read_requests"), f(st, "Innodb_buffer_pool_reads")
    hit = (1 - miss / reqs) * 100 if reqs else 100
    add("InnoDB", "Buffer pool hit ratio", f"{hit:.2f}%", level(hit, 99, 95, higher_is_bad=False))
    add("InnoDB", "Buffer pool size", fmt_bytes(f(var, "innodb_buffer_pool_size")))
    free, total = f(st, "Innodb_buffer_pool_pages_free"), f(st, "Innodb_buffer_pool_pages_total")
    add("InnoDB", "Buffer pool pages free", f"{free / total * 100:.0f}%" if total else "n/a")

    # --- Resources
    of_lim, of_open = f(var, "open_files_limit"), f(st, "Open_files")
    p = of_open / of_lim * 100 if of_lim else 0
    add("Resources", "Open files", f"{int(of_open)} / {int(of_lim)} ({p:.0f}%)", level(p, 70, 85))

    # --- Replication (8.4 syntax)
    repl = None
    try:
        repl = rows(cur, "SHOW REPLICA STATUS")
    except mysql.connector.Error:
        pass
    if repl:
        r = repl[0]
        io, sql_ = r.get("Replica_IO_Running"), r.get("Replica_SQL_Running")
        lag = r.get("Seconds_Behind_Source")
        add("Replication", "IO / SQL thread", f"{io} / {sql_}",
            OK if io == "Yes" and sql_ == "Yes" else CRIT, r.get("Last_Error") or "")
        add("Replication", "Seconds behind source", lag if lag is not None else "NULL",
            CRIT if lag is None else level(lag, 30, 300))
    else:
        add("Replication", "Replica status", "Not a replica / not configured")

    # --- Long running queries
    plist = rows(cur, "SHOW FULL PROCESSLIST")
    long_q = [p for p in plist
              if p["Command"] not in ("Sleep", "Daemon", "Binlog Dump", "Binlog Dump GTID")
              and (p["Time"] or 0) >= 60 and p["User"] != "event_scheduler"]
    add("Performance", "Queries running > 60s", len(long_q), WARN if long_q else OK)

    # --- Databases
    dbs = rows(cur, """
        SELECT table_schema AS db, COUNT(*) AS tbls,
               COALESCE(SUM(data_length),0) AS data, COALESCE(SUM(index_length),0) AS idx
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema','performance_schema','sys','mysql')
        GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC""")
    big = rows(cur, """
        SELECT table_schema AS db, table_name AS tbl, table_rows AS est_rows,
               data_length AS data, index_length AS idx
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema','performance_schema','sys','mysql')
        ORDER BY data_length+index_length DESC LIMIT 10""")
    cur.close()
    return dict(checks=checks, long_q=long_q, dbs=dbs, big=big)


def worst(checks):
    w = OK
    for _, _, _, s, _ in checks:
        if RANK[s] > RANK[w]:
            w = s
    return w


# ---------------------------------------------------------------- connection
def check_server(srv):
    name = srv["name"]
    key = env_key(name)
    tunnel = None
    host, port = srv["host"], int(srv.get("port", 3306))
    try:
        if srv.get("ssh"):
            from sshtunnel import SSHTunnelForwarder  # optional dependency
            s = srv["ssh"]
            ssh_pwd = get_secret(f"SSH_PWD_{key}", f"[{name}] SSH password for {s['user']}@{s['host']}: ")
            tunnel = SSHTunnelForwarder(
                (s["host"], int(s.get("port", 22))),
                ssh_username=s["user"], ssh_password=ssh_pwd,
                remote_bind_address=(s.get("mysql_host_from_server", "127.0.0.1"), port),
                local_bind_address=("127.0.0.1", 0))
            tunnel.start()
            host, port = "127.0.0.1", tunnel.local_bind_port
        pwd = get_secret(f"MYSQL_PWD_{key}", f"[{name}] MySQL password for {srv['user']}: ")
        kw = dict(host=host, port=port, user=srv["user"], password=pwd,
                  connection_timeout=int(srv.get("timeout", 10)))
        if srv.get("ssl_ca"):
            kw.update(ssl_ca=srv["ssl_ca"], ssl_verify_cert=True)
        conn = mysql.connector.connect(**kw)
        try:
            data = collect(conn)
        finally:
            conn.close()
        data.update(name=name, target=f"{srv['host']}:{srv.get('port', 3306)}",
                    status=worst(data["checks"]), error=None)
        return data
    except Exception as e:  # noqa: BLE001 - report any failure in the HTML
        return dict(name=name, target=f"{srv['host']}:{srv.get('port', 3306)}", status=CRIT,
                    error=f"{type(e).__name__}: {e}", checks=[], long_q=[], dbs=[], big=[])
    finally:
        if tunnel:
            tunnel.stop()


# ---------------------------------------------------------------- HTML
CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f9;color:#1f2933}
header{background:#1d3557;color:#fff;padding:20px 32px}
header h1{margin:0;font-size:22px}header p{margin:4px 0 0;opacity:.8;font-size:13px}
main{max-width:1100px;margin:24px auto;padding:0 16px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:18px 22px;margin-bottom:22px}
h2{margin:0 0 12px;font-size:18px}h3{margin:20px 0 8px;font-size:14px;color:#52606d;text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;background:#eef1f5;padding:7px 10px}td{padding:7px 10px;border-top:1px solid #e4e7eb;vertical-align:top}
.b{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;color:#fff}
.OK{background:#2e9e5b}.INFO{background:#7b8794}.WARN{background:#e89a0c}.CRIT{background:#d64545}
.err{background:#fdecec;border-left:4px solid #d64545;padding:10px 14px;font-family:Consolas,monospace;font-size:13px}
.num{text-align:right;font-variant-numeric:tabular-nums}
"""


def badge(s):
    return f'<span class="b {s}">{s}</span>'


def esc(x):
    return html.escape("" if x is None else str(x))


def table(headers, body_rows, num_cols=()):
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    b = ""
    for r in body_rows:
        b += "<tr>" + "".join(
            f'<td class="{"num" if i in num_cols else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>"
    return f"<table><tr>{h}</tr>{b}</table>"


def render(results, generated):
    summary = table(["Server", "Target", "Status", "Warnings", "Critical"], [
        [f'<a href="#{esc(r["name"])}">{esc(r["name"])}</a>', esc(r["target"]), badge(r["status"]),
         sum(1 for c in r["checks"] if c[3] == WARN),
         sum(1 for c in r["checks"] if c[3] == CRIT) + (1 if r["error"] else 0)] for r in results])
    out = [f"<!doctype html><html><head><meta charset='utf-8'><title>MySQL Health Report</title>"
           f"<style>{CSS}</style></head><body><header><h1>MySQL Health Report</h1>"
           f"<p>Generated {esc(generated)}</p></header><main>",
           f'<div class="card"><h2>Overview</h2>{summary}</div>']
    for r in results:
        out.append(f'<div class="card" id="{esc(r["name"])}"><h2>{esc(r["name"])} '
                   f'{badge(r["status"])} <small style="font-weight:normal;color:#7b8794">{esc(r["target"])}</small></h2>')
        if r["error"]:
            out.append(f'<div class="err">Could not check this server.<br>{esc(r["error"])}</div></div>')
            continue
        # group checks by category
        cats = {}
        for cat, name, val, status, note in r["checks"]:
            cats.setdefault(cat, []).append([esc(name), esc(val), badge(status), esc(note)])
        for cat, body in cats.items():
            out.append(f"<h3>{esc(cat)}</h3>" + table(["Check", "Value", "Status", "Note"], body))
        if r["long_q"]:
            out.append("<h3>Long-running queries (&ge; 60s)</h3>" + table(
                ["ID", "User", "DB", "Time (s)", "State", "Query"],
                [[p["Id"], esc(p["User"]), esc(p["db"]), p["Time"], esc(p["State"]),
                  esc((p["Info"] or "")[:200])] for p in r["long_q"]], num_cols=(3,)))
        if r["dbs"]:
            out.append("<h3>Databases by size</h3>" + table(
                ["Database", "Tables", "Data", "Indexes", "Total"],
                [[esc(d["db"]), d["tbls"], fmt_bytes(d["data"]), fmt_bytes(d["idx"]),
                  fmt_bytes(float(d["data"]) + float(d["idx"]))] for d in r["dbs"]],
                num_cols=(1, 2, 3, 4)))
        if r["big"]:
            out.append("<h3>Top 10 largest tables</h3>" + table(
                ["Table", "Est. rows", "Data", "Indexes"],
                [[esc(f'{t["db"]}.{t["tbl"]}'), f'{int(t["est_rows"] or 0):,}', fmt_bytes(t["data"]),
                  fmt_bytes(t["idx"])] for t in r["big"]], num_cols=(1, 2, 3)))
        out.append("</div>")
    out.append("</main></body></html>")
    return "".join(out)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="MySQL health report")
    ap.add_argument("-c", "--config", default="servers.json")
    ap.add_argument("-o", "--outdir", default="reports")
    ap.add_argument("--open", action="store_true", help="open report in browser")
    a = ap.parse_args()

    with open(a.config, encoding="utf-8") as fh:
        servers = json.load(fh)["servers"]
    results = []
    for s in servers:
        print(f"Checking {s['name']} ...")
        results.append(check_server(s))
        print(f"  -> {results[-1]['status']}" + (f"  {results[-1]['error']}" if results[-1]["error"] else ""))

    now = dt.datetime.now()
    os.makedirs(a.outdir, exist_ok=True)
    path = os.path.abspath(os.path.join(a.outdir, f"mysql_health_{now:%Y%m%d_%H%M%S}.html"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(results, now.strftime("%Y-%m-%d %H:%M:%S")))
    print(f"\nReport: {path}")
    if a.open:
        webbrowser.open("file:///" + path.replace("\\", "/"))
    sys.exit(max(RANK[r["status"]] for r in results))


if __name__ == "__main__":
    main()
