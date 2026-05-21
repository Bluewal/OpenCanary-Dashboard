from flask import Flask, render_template, jsonify, Response
import json, csv, io, os
from datetime import datetime

app = Flask(__name__)

LOG_FILE = os.getenv("OPENCANARY_LOG", "/var/tmp/opencanary.log")

LOGTYPES = {
    2000: ("FTP",    "Tentative FTP"),
    2001: ("FTP",    "Tentative FTP"),
    3000: ("HTTP",   "Requête HTTP GET"),
    3001: ("HTTP",   "Login HTTP"),
    3002: ("HTTP",   "Méthode HTTP inconnue"),
    3003: ("HTTP",   "Redirect HTTP"),
    4000: ("SSH",    "Connexion SSH"),
    4001: ("SSH",    "Handshake SSH"),
    4002: ("SSH",    "Tentative SSH"),
    6001: ("Telnet", "Tentative Telnet"),
    6002: ("Telnet", "Connexion Telnet"),
    8001: ("MySQL",  "Tentative MySQL"),
    9003: ("MySQL",  "Connexion MySQL"),
    14001:("RDP",    "Connexion RDP"),
    17001:("Redis",  "Commande Redis"),
}

def time_ago(ts):
    try:
        diff = int((datetime.now() - datetime.fromisoformat(ts)).total_seconds())
        if diff < 60: return f"{diff}s"
        if diff < 3600: return f"{diff//60}m"
        if diff < 86400: return f"{diff//3600}h"
        return f"{diff//86400}j"
    except: return ""

def parse_logs():
    events, stats, ip_counts, creds = [], {"SSH":0,"HTTP":0,"RDP":0,"FTP":0,"Telnet":0,"MySQL":0,"Redis":0}, {}, {}
    hourly = {str(i).zfill(2):0 for i in range(24)}
    try:
        with open(LOG_FILE) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    lt = e.get("logtype")
                    if lt not in LOGTYPES: continue
                    service, label = LOGTYPES[lt]
                    ld = e.get("logdata", {})
                    detail = ""
                    if lt == 4002:
                        u, p = ld.get("USERNAME","?"), ld.get("PASSWORD","?")
                        detail = f"{u} / {p}"
                        creds[f"{u}:{p}"] = creds.get(f"{u}:{p}", 0) + 1
                    elif lt == 3001: detail = f"{ld.get('USERNAME','?')} / {ld.get('PASSWORD','?')}"
                    elif lt == 6001: detail = f"{ld.get('USERNAME','?')} / {ld.get('PASSWORD','?')}"
                    elif lt in (4000,4001): detail = ld.get("REMOTEVERSION","")
                    elif lt in (3000,3002,3003): detail = ld.get("PATH","")
                    elif lt == 17001: detail = ld.get("CMD","")
                    src = e.get("src_host","")
                    ts = e.get("local_time","")
                    stats[service] = stats.get(service, 0) + 1
                    if src: ip_counts[src] = ip_counts.get(src,0) + 1
                    try: hourly[ts[11:13]] += 1
                    except: pass
                    events.append({"time":ts[:19],"ago":time_ago(ts[:19]),"service":service,"label":label,"detail":detail,"src":src,"dst_port":e.get("dst_port","")})
                except: continue
    except: pass
    events.reverse()
    return (events[:100], stats,
            sorted(ip_counts.items(), key=lambda x:x[1], reverse=True)[:5],
            sorted(creds.items(), key=lambda x:x[1], reverse=True)[:5],
            [{"h":h,"v":v} for h,v in sorted(hourly.items())])

@app.route("/")
def index():
    ev, st, ips, cr, hr = parse_logs()
    return render_template("index.html", events=ev, stats=st, top_ips=ips, top_creds=cr, hourly=hr)

@app.route("/api/events")
def api_events():
    ev, st, ips, cr, hr = parse_logs()
    return jsonify({"events":ev,"stats":st,"top_ips":ips,"top_creds":cr,"hourly":hr})

@app.route("/api/export")
def export():
    ev, *_ = parse_logs()
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=["time","service","label","detail","src","dst_port"])
    w.writeheader()
    w.writerows([{k:v for k,v in e.items() if k != "ago"} for e in ev])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=opencanary.csv"})

if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", 8080))
    app.run(host="0.0.0.0", port=port)
