import json
import os
import secrets
import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie

# ==========================================
# CONFIGURATION
# ==========================================
CONFIG = {
    "log_file":              "/var/ossec/logs/alerts/alerts.json",
    "db_file":               "soc_database.json",
    "tail_lines":            10000,
    "timezone_offset_hours": 1,
    "port":                  8080,
    "bind_address":          "0.0.0.0",
    "dashboard_ip":          "192.168.1.107",
    "target_rule_ids":       ["100115", "100116", "100117", "100050", "100051", "100102", "100104"],
    "critical_level":        10,
    "high_level":            7,
    "keyword_level":         3,
    "soar_keyword":          "anaos soar: blocked ip",
    "auth_username":         "admin",
    "auth_salt":             "anaos_soc_secure_salt_2026",
    "auth_password_hash":    "6640c31623910f135b1285223c723f666f7f2b966d9b4b66d626359d99723528",
    "session_timeout_minutes": 120
}

# ==========================================
# STATE MANAGEMENT
# ==========================================
ACTIVE_SESSIONS = {}
DB_STATE = {
    "triage_decisions": {}, 
    "ip_first_seen": {}
}

def load_db():
    global DB_STATE
    if not os.path.exists(CONFIG["db_file"]):
        return
    try:
        with open(CONFIG["db_file"], 'r') as f:
            DB_STATE = json.load(f)
        print(f"[+] Local DB loaded: {len(DB_STATE['triage_decisions'])} triage decisions, {len(DB_STATE['ip_first_seen'])} IPs tracked.")
    except Exception as e:
        print(f"[-] Error loading DB: {e}")

def save_db():
    try:
        with open(CONFIG["db_file"], 'w') as f:
            json.dump(DB_STATE, f)
    except Exception as e:
        print(f"[-] Error saving DB: {e}")

# ==========================================
# AUTHENTICATION HELPERS
# ==========================================
def verify_credentials(username, password):
    # TEMPORARY BYPASS FOR DEBUGGING
    return username == "admin" and password == "admin"

def create_session():
    token = secrets.token_hex(32)
    ACTIVE_SESSIONS[token] = datetime.now() + timedelta(minutes=CONFIG["session_timeout_minutes"])
    return token

def is_session_valid(token):
    if not token or token not in ACTIVE_SESSIONS:
        return False
    if datetime.now() > ACTIVE_SESSIONS[token]:
        del ACTIVE_SESSIONS[token]
        return False
    return True

def generate_alert_id(ts_str, rule_id, src_ip):
    raw = f"{ts_str}|{rule_id}|{src_ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

# ==========================================
# DATA ENGINE
# ==========================================
def extract_suricata_data(alert):
    data = alert.get("data", {})
    alert_block = data.get("alert", {})
    meta = alert_block.get("metadata", {}) if isinstance(alert_block, dict) else {}
    http = data.get("http", {}) if isinstance(data.get("http"), dict) else {}

    return {
        "suricata_sig":   alert_block.get("signature", "") if isinstance(alert_block, dict) else "",
        "suri_src_ip":    data.get("src_ip", "") or data.get("srcip", ""),
        "http_url":       http.get("url", ""),
        "user_agent":     http.get("http_user_agent", ""),
        "mitre_tac_sur":  meta.get("mitre_tactic_name", []) if isinstance(meta, dict) else [],
        "mitre_tech_sur": meta.get("mitre_technique_id", []) if isinstance(meta, dict) else [],
    }

def build_search_surface(alert, desc, full_log):
    parts = [str(desc), str(full_log)]
    try:
        sig = alert.get("data", {}).get("alert", {}).get("signature", "")
        if sig: parts.append(str(sig))
    except AttributeError:
        pass

    groups = alert.get("rule", {}).get("groups", [])
    if isinstance(groups, list):
        parts.extend([str(g) for g in groups])

    try:
        parts.extend([v for v in alert.get("data", {}).values() if isinstance(v, str)])
    except AttributeError:
        pass

    return " ".join(parts).lower()

def fetch_parsed_alerts():
    events = []
    db_changed = False
    log_file_path = CONFIG["log_file"]

    try:
        raw_output = subprocess.check_output(
            ['tail', '-n', str(CONFIG["tail_lines"]), log_file_path],
            stderr=subprocess.STDOUT
        )
        lines = raw_output.decode('utf-8', errors='replace').split('\n')
    except subprocess.CalledProcessError as e:
        print(f"[-] Tail failed: {e}")
        return []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            alert   = json.loads(line)
            
            # 1. Extraction du timestamp en premier
            ts_str = alert.get("timestamp", "")
            if not ts_str:
                continue
                
            utc_time = datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            raw_time_val = utc_time.timestamp()

            # 2. Extraction de l'IP en deuxième
            src_ip = "local"
            for ip_field in [alert.get("data", {}).get("src_ip"), alert.get("data", {}).get("srcip"), 
                             alert.get("network", {}).get("srcip"), alert.get("agent", {}).get("ip")]:
                if ip_field:
                    src_ip = ip_field
                    break

            # =========================================================
            # 3. ENREGISTREMENT DE T0 SUR *TOUS* LES LOGS (Sans filtrage)
            # =========================================================
            if src_ip not in DB_STATE["ip_first_seen"] or raw_time_val < DB_STATE["ip_first_seen"][src_ip]:
                DB_STATE["ip_first_seen"][src_ip] = raw_time_val
                db_changed = True

            # =========================================================
            # 4. FILTRAGE POUR L'AFFICHAGE DU DASHBOARD
            # =========================================================
            rule    = alert.get("rule", {})
            rule_id = str(rule.get("id", ""))
            
            if rule_id not in CONFIG["target_rule_ids"]:
                continue # Si ce n'est pas une alerte ciblée, on s'arrête là pour l'affichage
                
            # --- À partir d'ici, on ne traite que les alertes de votre liste ---
            level  = int(rule.get("level", 0))
            desc   = str(rule.get("description", "Unknown Event"))
            groups = rule.get("groups", [])
            if not isinstance(groups, list): groups = [str(groups)]

            mitre      = rule.get("mitre", {})
            mitre_tac  = mitre.get("tactic", [])
            mitre_tech = mitre.get("technique", [])
            mitre_ids  = mitre.get("id", [])

            if not isinstance(mitre_tac, list): mitre_tac = [mitre_tac]
            if not isinstance(mitre_tech, list): mitre_tech = [mitre_tech]
            if not isinstance(mitre_ids, list): mitre_ids = [mitre_ids]

            suri = extract_suricata_data(alert)
            mitre_tac.extend([str(t).replace("_", " ").title() for t in suri.get("mitre_tac_sur", []) if str(t).replace("_", " ").title() not in mitre_tac])
            mitre_ids.extend([t for t in suri.get("mitre_tech_sur", []) if t not in mitre_ids])

            display_desc = suri["suricata_sig"] if suri.get("suricata_sig") and ("suricata alert" in desc.lower() or "anaos_soc" in " ".join(groups).lower()) else desc
            
            local_time = utc_time + timedelta(hours=CONFIG["timezone_offset_hours"])

            events.append({
                "alert_id":       generate_alert_id(ts_str, rule_id, src_ip),
                "timestamp":      local_time.strftime("%Y-%m-%d %H:%M:%S"),
                "raw_time":       raw_time_val,
                "t0_time":        DB_STATE["ip_first_seen"][src_ip], # On attache le T0 trouvé au point 3
                "level":          level,
                "desc":           display_desc,
                "raw_desc":       desc,
                "ip":             src_ip,
                "mitre":          mitre_tac,
                "mitre_ids":      mitre_ids,
                "mitre_tech":     mitre_tech,
                "rule_id":        rule_id,
                "groups":         groups,
                "agent_name":     alert.get("agent", {}).get("name", "unknown"),
                "agent_id":       alert.get("agent", {}).get("id", "000"),
                "suricata_sig":   suri.get("suricata_sig", ""),
                "http_url":       suri.get("http_url", ""),
                "user_agent":     suri.get("user_agent", ""),
                "search_surface": build_search_surface(alert, desc, str(alert.get("full_log", ""))[:500]),
            })

        except Exception as e:
            print(f"[-] Parse error skipping line: {type(e).__name__} - {e}")
            continue
    
    if db_changed:
        save_db()

    return events

# ==========================================
# FRONTEND HTML/JS/CSS (Collapsed for readability)
# ==========================================
LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANAOS SOC — Gatekeeper</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0d0f12; color: #e4e6eb; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-card { background: #161a1f; border: 1px solid #2a313a; padding: 32px; border-radius: 8px; width: 100%; max-width: 380px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        .brand { text-align: center; margin-bottom: 24px; }
        .brand h2 { font-size: 20px; color: #ffffff; letter-spacing: 0.05em; font-weight: 600; }
        .brand p { font-size: 11px; color: #8a94a6; margin-top: 4px; text-transform: uppercase; }
        .group { margin-bottom: 18px; }
        label { display: block; font-size: 11px; color: #8a94a6; text-transform: uppercase; margin-bottom: 6px; letter-spacing: 0.04em; }
        input { width: 100%; background: #0d0f12; border: 1px solid #2a313a; border-radius: 4px; padding: 10px 12px; color: #fff; font-size: 14px; outline: none; }
        input:focus { border-color: #1a5fa8; }
        .btn { width: 100%; background: #1a5fa8; color: #fff; border: none; padding: 11px; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; transition: background 0.15s; }
        .btn:hover { background: #226ec2; }
        .err { background: rgba(192,57,43,0.15); border: 1px solid #c0392b; color: #fccbc6; padding: 10px; border-radius: 4px; font-size: 12px; margin-bottom: 16px; display: none; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="brand">
            <h2>ANAOS SOC ENGINE</h2>
            <p>Identity Verification Control</p>
        </div>
        <div class="err" id="errBlock">Invalid identity or security token payload.</div>
        <form onsubmit="handleLogin(event)">
            <div class="group"><label>Username</label><input type="text" id="user" required autocomplete="off"></div>
            <div class="group"><label>Password</label><input type="password" id="pass" required></div>
            <button type="submit" class="btn">Authenticate</button>
        </form>
    </div>
    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const errBlock = document.getElementById('errBlock');
            errBlock.style.display = 'none';
            const r = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ u: document.getElementById('user').value, p: document.getElementById('pass').value })
            });
            if (r.ok) { window.location.href = '/'; }
            else { errBlock.style.display = 'block'; }
        }
    </script>
</body>
</html>"""

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ANAOS SOC</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --bg: #f5f5f5; --surface: #ffffff; --surface2: #fafafa; --border: #e0e0e0; --border2: #d0d0d0; --text: #1a1a1a; --text2: #555555; --text3: #999999; --red: #c0392b; --red-bg: #fdf2f1; --red-bd: #f0c4c0; --amber: #b7770d; --amber-bg: #fdf8ee; --amber-bd: #f0dfa0; --blue: #1a5fa8; --blue-bg: #eef4fc; --blue-bd: #b8d0f0; --green: #1e7e34; --green-bg: #f0faf2; --green-bd: #a8d8b0; --gray-bg: #f0f0f0; --gray-bd: #d8d8d8; --radius: 6px; --mono: 'Courier New', Courier, monospace; }
html, body { background: var(--bg); color: var(--text); font-family: system-ui,-apple-system,sans-serif; font-size: 14px; line-height: 1.5; min-height: 100vh; }
.shell { max-width: 1700px; margin: 0 auto; padding: 24px; }
.header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
.brand-name { font-size: 17px; font-weight: 600; color: var(--text); }
.status-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.live-dot { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text2); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); }
.clock { font-family: var(--mono); font-size: 12px; color: var(--text2); background: var(--surface); border: 1px solid var(--border); padding: 3px 9px; border-radius: var(--radius); }
.finput { background: var(--surface); border: 1px solid var(--border2); color: var(--text); padding: 6px 10px; border-radius: var(--radius); font-size: 13px; outline: none; }
.finput:focus { border-color: var(--blue); box-shadow: 0 0 0 2px rgba(26,95,168,0.1); }
.btn { padding: 7px 16px; border: 1px solid var(--border2); background: var(--surface); color: var(--text); border-radius: var(--radius); font-size: 13px; cursor: pointer; transition: background 0.1s; }
.btn:hover { background: var(--bg); }
.btn-red   { border-color: var(--red-bd);   color: var(--red);   background: var(--red-bg);   }
.btn-red:hover   { background: #fce8e6; }
.btn-amber { border-color: var(--amber-bd); color: var(--amber); background: var(--amber-bg); }
.btn-amber:hover { background: #faf3d8; }
.kpi-row { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 20px; }
@media(max-width:900px) { .kpi-row { grid-template-columns: repeat(2,1fr); } }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; border-top: 3px solid transparent; }
.kpi-lbl { font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
.kpi-val { font-size: 28px; font-weight: 600; line-height: 1; }
.kpi-hint { font-size: 11px; color: var(--text3); margin-top: 5px; }
.k-tp   { border-top-color: var(--red);   } .k-tp   .kpi-val { color: var(--red);   }
.k-fp   { border-top-color: var(--amber); } .k-fp   .kpi-val { color: var(--amber); }
.k-fpr  { border-top-color: var(--blue);  } .k-fpr  .kpi-val { color: var(--blue);  }
.k-mttt { border-top-color: var(--green); } .k-mttt .kpi-val { color: var(--green); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 16px; }
.ph { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--surface2); flex-wrap: wrap; gap: 8px; }
.ph-title { font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.06em; }
.pb { padding: 14px; }
.agent-strip { display: flex; flex-wrap: wrap; gap: 8px; }
.agent-chip { display: flex; align-items: center; gap: 7px; background: var(--surface2); border: 1px solid var(--border); border-radius: var(--radius); padding: 5px 12px; }
.a-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); flex-shrink: 0; }
.a-name { font-size: 12px; color: var(--text); }
.a-cnt { font-size: 11px; color: var(--text3); }
.tab-bar { display: flex; gap: 4px; }
.tab { padding: 4px 12px; border: 1px solid var(--border2); background: var(--surface); color: var(--text2); border-radius: var(--radius); font-size: 12px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
.tab:hover { background: var(--bg); }
.tab.active { background: var(--blue); color: #fff; border-color: var(--blue); }
.tab-count { font-size: 10px; background: rgba(255,255,255,0.25); border-radius: 8px; padding: 0 5px; margin-left: 4px; }
.tab:not(.active) .tab-count { background: var(--gray-bg); color: var(--text3); }
.tbl-outer { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
thead tr { background: var(--surface2); }
th { padding: 9px 12px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text3); white-space: nowrap; cursor: pointer; user-select: none; border-bottom: 1px solid var(--border); }
th:hover { color: var(--text); }
td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; color: var(--text); }
tr:last-child td { border: none; }
tr.row-tp td { background: rgba(192,57,43,0.04); }
tr.row-fp td { background: rgba(183,119,13,0.04); }
tr.row-tp:hover td { background: rgba(192,57,43,0.09); }
tr.row-fp:hover td { background: rgba(183,119,13,0.09); }
tr.row-pend:hover td { background: var(--surface2); }
.badge { display: inline-block; padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: 600; white-space: nowrap; }
.b-crit  { background: var(--red-bg);   color: var(--red);   border: 1px solid var(--red-bd);   }
.b-high  { background: #fff3e8;         color: #b05a00;      border: 1px solid #f0c898;         }
.b-med   { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-bd);  }
.b-low   { background: var(--gray-bg);  color: var(--text3); border: 1px solid var(--gray-bd);   }
.b-suri  { background: var(--blue-bg);  color: var(--blue);  border: 1px solid var(--blue-bd);   }
.b-soar  { background: #f0f8f0;         color: #1a6b2a;      border: 1px solid #a8d8b0;         }
.b-pend  { background: var(--gray-bg);  color: var(--text3); border: 1px solid var(--gray-bd);   }
.b-tp    { background: var(--red-bg);   color: var(--red);   border: 1px solid var(--red-bd);    }
.b-fp    { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-bd);  }
.triage-wrap { display: flex; gap: 5px; align-items: center; white-space: nowrap; }
.t-btn { padding: 3px 9px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid; transition: all 0.12s; line-height: 1.4; }
.t-tp  { background: var(--surface); color: var(--red);   border-color: var(--red-bd);   }
.t-tp:hover, .t-tp.active  { background: var(--red);   color: #fff; border-color: var(--red);   }
.t-fp  { background: var(--surface); color: var(--amber); border-color: var(--amber-bd); }
.t-fp:hover, .t-fp.active  { background: var(--amber); color: #fff; border-color: var(--amber); }
.ip-c    { font-family: var(--mono); color: var(--blue); font-size: 12px; }
.agent-c { font-size: 11px; color: var(--text3); }
.desc-c  { max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rule-c  { font-family: var(--mono); font-size: 11px; color: var(--amber); }
.mitre-c { font-size: 11px; color: var(--text2); }
.empty { text-align: center; padding: 28px; font-size: 12px; color: var(--text3); }
.spin { width: 28px; height: 28px; border: 2px solid var(--border); border-top-color: var(--blue); border-radius: 50%; animation: spin .7s linear infinite; margin: 0 auto 10px; }
@keyframes spin { to { transform: rotate(360deg); } }
.triage-progress { display: flex; align-items: center; gap: 10px; font-size: 11px; color: var(--text3); }
.prog-bar { flex: 1; height: 4px; background: var(--gray-bg); border-radius: 2px; overflow: hidden; min-width: 80px; max-width: 160px; }
.prog-fill { height: 100%; background: var(--green); border-radius: 2px; transition: width 0.3s; }
</style>
</head>
<body>
<div class="shell">

<header class="header">
  <div>
    <div class="brand-name">ANAOS SOC Engine</div>
  </div>
  <div class="status-row">
    <button class="btn btn-red" onclick="logout()" style="padding:4px 10px;font-size:11px;">Logout</button>
    <div class="live-dot"><div class="dot"></div><span id="liveLabel">Live</span></div>
    <div class="clock" id="clockDisplay">--:--:--</div>
  </div>
</header>

<div class="kpi-row">
  <div class="kpi k-tp">
    <div class="kpi-lbl">True Positives</div>
    <div class="kpi-val" id="tpCount">0</div>
    <div class="kpi-hint">Confirmed threats</div>
  </div>
  <div class="kpi k-fp">
    <div class="kpi-lbl">False Positives</div>
    <div class="kpi-val" id="fpCount">0</div>
    <div class="kpi-hint">Noise / benign</div>
  </div>
  <div class="kpi k-fpr">
    <div class="kpi-lbl">FPR</div>
    <div class="kpi-val" id="fprRate">0%</div>
    <div class="kpi-hint">False positive rate</div>
  </div>
  <div class="kpi k-mttt">
    <div class="kpi-lbl">MTTD</div>
    <div class="kpi-val" id="mtttTime">—</div>
    <div class="kpi-hint">Mean time to detect</div>
  </div>
</div>

<div class="panel">
  <div class="ph"><span class="ph-title">Active Agents</span></div>
  <div class="pb"><div class="agent-strip" id="agentStrip"><div class="empty">Loading…</div></div></div>
</div>

<div class="panel">
  <div class="ph">
    <span class="ph-title">Triage Console</span>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <div class="triage-progress">
        <span id="triageProgressLabel">0 / 0 triaged</span>
        <div class="prog-bar"><div class="prog-fill" id="triageProgressFill" style="width:0%"></div></div>
      </div>
      <div class="tab-bar">
        <button class="tab active" id="tabAll"     onclick="setTab('all')">All<span class="tab-count" id="cntAll">0</span></button>
        <button class="tab"        id="tabPending" onclick="setTab('pending')">Pending<span class="tab-count" id="cntPending">0</span></button>
        <button class="tab"        id="tabTp"      onclick="setTab('tp')">Confirmed TP<span class="tab-count" id="cntTp">0</span></button>
        <button class="tab"        id="tabFp"      onclick="setTab('fp')">Confirmed FP<span class="tab-count" id="cntFp">0</span></button>
      </div>
      <input class="finput" type="text" id="tableSearch" placeholder="Search…" oninput="renderTable()" style="width:160px;padding:4px 8px;font-size:12px">
    </div>
  </div>
  <div class="tbl-outer">
    <table>
      <thead>
        <tr>
          <th onclick="sortTable('timestamp')">Timestamp</th>
          <th onclick="sortTable('ip')">Source IP</th>
          <th onclick="sortTable('level')">Level</th>
          <th>Agent</th>
          <th onclick="sortTable('rule_id')">Rule</th>
          <th onclick="sortTable('desc')">Description</th>
          <th>MITRE</th>
          <th>Context</th>
          <th>Triage Action</th>
        </tr>
      </thead>
      <tbody id="triageTableBody">
        <tr><td colspan="9"><div class="empty"><div class="spin"></div>Loading…</div></td></tr>
      </tbody>
    </table>
  </div>
</div>

</div>

<script>
let allAlerts  = [];
let triageMap  = {};
let filteredAlerts = [];
let sortKey    = 'timestamp';
let sortAsc    = false;
let activeTab  = 'all';

const fmtDur = s => {
  if (!s || s <= 0) return '0s';
  if (s < 60)   return s.toFixed(1)+'s';
  if (s < 3600) return (s/60).toFixed(1)+'m';
  return (s/3600).toFixed(2)+'h';
};

function lvBadge(lv) {
  if (lv >= 10) return `<span class="badge b-crit">CRIT ${lv}</span>`;
  if (lv >= 7)  return `<span class="badge b-high">HIGH ${lv}</span>`;
  if (lv >= 5)  return `<span class="badge b-med">MED ${lv}</span>`;
  return               `<span class="badge b-low">LOW ${lv}</span>`;
}

function srcBadges(a) {
  let b = '';
  if (a.suricata_sig) b += `<span class="badge b-suri" style="margin-left:3px">Suricata</span>`;
  if ((a.desc||'').toLowerCase().includes('anaos soar: blocked ip')) b += `<span class="badge b-soar" style="margin-left:3px">SOAR</span>`;
  return b;
}

function triageBtns(alertId, rawTime, verdict) {
  const tpActive = verdict === 'tp' ? 'active' : '';
  const fpActive = verdict === 'fp' ? 'active' : '';
  return `<div class="triage-wrap">
    <button class="t-btn t-tp ${tpActive}" onclick="triage('${alertId}','tp',${rawTime})">TP</button>
    <button class="t-btn t-fp ${fpActive}" onclick="triage('${alertId}','fp',${rawTime})">FP</button>
  </div>`;
}

async function loadData() {
  try {
    const [alertsRes, triageRes] = await Promise.all([
      fetch('/api/alerts'),
      fetch('/api/triage'),
    ]);
    if (alertsRes.status === 401) { window.location.href = '/login'; return; }
    allAlerts = await alertsRes.json();
    triageMap = await triageRes.json();
    applyFilters();
  } catch (e) {
    document.getElementById('liveLabel').textContent = 'Connection failed';
    document.getElementById('liveLabel').style.color = 'var(--red)';
  }
}

async function logout() {
  await fetch('/logout', { method: 'POST' });
  window.location.href = '/login';
}

async function triage(alertId, verdict, alertRawTime) {
  const existing = triageMap[alertId];
  const newVerdict = (existing && existing.verdict === verdict) ? null : verdict;

  if (newVerdict) {
    triageMap[alertId] = {
      verdict:        newVerdict,
      triaged_at:     Date.now() / 1000,
      alert_raw_time: alertRawTime,
    };
  } else {
    delete triageMap[alertId];
  }

  updateKPIs();
  renderTable();

  try {
    await fetch('/api/triage', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        alert_id:       alertId,
        verdict:        newVerdict || 'remove',
        alert_raw_time: alertRawTime,
      }),
    });
  } catch (e) { console.error('Triage save failed:', e); }
}

function setTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
  renderTable();
}

function applyFilters() {
  filteredAlerts = allAlerts.slice();
  filteredAlerts.sort((a, b) => a.raw_time - b.raw_time);
  updateKPIs();
  renderAgents();
  renderTable();
}

function updateKPIs() {
  const withVerdict = filteredAlerts.map(a => ({
    ...a,
    verdict: (triageMap[a.alert_id] || {}).verdict || 'pending',
  }));

  const tpAlerts = withVerdict.filter(a => a.verdict === 'tp');
  const fpAlerts = withVerdict.filter(a => a.verdict === 'fp');
  const total    = tpAlerts.length + fpAlerts.length;
  const fpr      = total > 0 ? (fpAlerts.length / total * 100) : 0;

  document.getElementById('tpCount').textContent = tpAlerts.length;
  document.getElementById('fpCount').textContent = fpAlerts.length;
  document.getElementById('fprRate').textContent = fpr.toFixed(1) + '%';

  let totalMttd = 0;
  let mttdCount = 0;

  tpAlerts.forEach(a => {
    const t1 = a.raw_time;
    const t0 = a.t0_time; 
    if (t0 && t1 >= t0) {
        totalMttd += (t1 - t0);
        mttdCount++;
    }
  });

  const mttd = mttdCount > 0 ? (totalMttd / mttdCount) : 0;
  document.getElementById('mtttTime').textContent = mttdCount > 0 ? fmtDur(mttd) : '—';

  const triaged = withVerdict.filter(a => a.verdict !== 'pending').length;
  const total2  = withVerdict.length;
  const pct     = total2 > 0 ? (triaged / total2 * 100) : 0;
  document.getElementById('triageProgressLabel').textContent = `${triaged} / ${total2} triaged`;
  document.getElementById('triageProgressFill').style.width  = pct.toFixed(1) + '%';

  document.getElementById('cntAll').textContent     = withVerdict.length;
  document.getElementById('cntPending').textContent = withVerdict.filter(a => a.verdict === 'pending').length;
  document.getElementById('cntTp').textContent      = tpAlerts.length;
  document.getElementById('cntFp').textContent      = fpAlerts.length;
}

function renderAgents() {
  const agentMap = {};
  filteredAlerts.forEach(a => { agentMap[a.agent_name] = (agentMap[a.agent_name] || 0) + 1; });
  const entries = Object.entries(agentMap).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { document.getElementById('agentStrip').innerHTML = '<div class="empty">No agent data.</div>'; return; }
  document.getElementById('agentStrip').innerHTML = entries.map(([name, cnt]) =>
    `<div class="agent-chip"><div class="a-dot"></div><span class="a-name">${name}</span><span class="a-cnt">(${cnt})</span></div>`).join('');
}

function sortTable(key) {
  sortAsc = (sortKey === key) ? !sortAsc : false;
  sortKey = key;
  renderTable();
}

function renderTable() {
  const q = (document.getElementById('tableSearch').value || '').toLowerCase();
  let rows = filteredAlerts.map(a => ({ ...a, verdict: (triageMap[a.alert_id] || {}).verdict || 'pending' }));
  if (activeTab !== 'all') { rows = rows.filter(a => a.verdict === activeTab); }
  if (q) {
    rows = rows.filter(a => (a.desc||'').toLowerCase().includes(q) || (a.ip||'').includes(q) || (a.rule_id||'').includes(q) || (a.agent_name||'').toLowerCase().includes(q));
  }
  rows.sort((a, b) => {
    const va = a[sortKey] || '', vb = b[sortKey] || '';
    return (va < vb ? -1 : va > vb ? 1 : 0) * (sortAsc ? 1 : -1);
  });

  if (!rows.length) {
    document.getElementById('triageTableBody').innerHTML = `<tr><td colspan="9"><div class="empty">No alerts match the current filter.</div></td></tr>`;
    return;
  }

  document.getElementById('triageTableBody').innerHTML = rows.map(a => {
    const tactics = [...(a.mitre||[]), ...(a.mitre_ids||[])].slice(0, 2).join(', ') || '—';
    const ctx = a.http_url ? `<span style="font-family:var(--mono);font-size:11px;color:var(--text2)">${a.http_url.slice(0, 30)}</span>`
      : (a.user_agent ? `<span style="font-size:11px;color:var(--text3)">${a.user_agent.slice(0, 25)}</span>` : '—');
    const rowClass = a.verdict === 'tp' ? 'row-tp' : a.verdict === 'fp' ? 'row-fp' : 'row-pend';

    return `<tr class="${rowClass}">
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2);white-space:nowrap">${a.timestamp}</td>
      <td class="ip-c">${a.ip}</td>
      <td>${lvBadge(a.level)}${srcBadges(a)}</td>
      <td class="agent-c">${a.agent_name||'—'}</td>
      <td class="rule-c">${a.rule_id||'—'}</td>
      <td class="desc-c" title="${(a.desc||'').replace(/"/g,'&quot;')}">${a.desc||'—'}</td>
      <td class="mitre-c">${tactics}</td>
      <td>${ctx}</td>
      <td>${triageBtns(a.alert_id, a.raw_time, a.verdict)}</td>
    </tr>`;
  }).join('');
}

setInterval(() => { document.getElementById('clockDisplay').textContent = new Date().toLocaleTimeString(undefined, { hour12: false }); }, 1000);
loadData();
setInterval(loadData, 10000);
</script>
</body>
</html>"""

# ==========================================
# HTTP SERVER WITH SESSION MIDDLEWARE
# ==========================================
class SOCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Disable default logging to keep console clean

    def _send_response(self, code, content_type, body):
        """Helper to send HTTP response avoiding repetition."""
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code, data):
        self._send_response(code, 'application/json', json.dumps(data).encode('utf-8'))

    def _send_html(self, code, html_string):
        self._send_response(code, 'text/html; charset=utf-8', html_string.encode('utf-8'))

    def _get_session_token(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = SimpleCookie(cookie_header)
            return cookie['session_id'].value if 'session_id' in cookie else None
        return None

    def _require_auth(self):
        """Validates token, returns False and sends 401/303 if invalid."""
        if not is_session_valid(self._get_session_token()):
            if self.path.startswith('/api/'):
                self._send_json(401, {"error": "Unauthorized"})
            else:
                self.send_response(303)
                self.send_header('Location', '/login')
                self.end_headers()
            return False
        return True

    def do_POST(self):
        if self.path == '/login':
            try:
                length = int(self.headers.get('Content-Length', 0))
                creds = json.loads(self.rfile.read(length).decode('utf-8'))
                
                if verify_credentials(creds.get('u', ''), creds.get('p', '')):
                    token = create_session()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Set-Cookie', f'session_id={token}; Path=/; HttpOnly; SameSite=Strict')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "success"}).encode())
                else:
                    self._send_json(401, {"error": "Invalid credentials"})
            except Exception:
                self._send_json(400, {"error": "Bad request format"})

        elif self.path == '/logout':
            token = self._get_session_token()
            if token in ACTIVE_SESSIONS:
                del ACTIVE_SESSIONS[token]
            self.send_response(200)
            self.send_header('Set-Cookie', 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()

        elif self.path == '/api/triage':
            if not self._require_auth():
                return
            try:
                length = int(self.headers.get('Content-Length', 0))
                payload = json.loads(self.rfile.read(length).decode('utf-8'))
                
                alert_id = payload.get('alert_id', '').strip()
                verdict = payload.get('verdict', '').strip()

                if not alert_id:
                    return self._send_json(400, {"error": "Missing alert_id"})

                if verdict == 'remove':
                    DB_STATE["triage_decisions"].pop(alert_id, None)
                elif verdict in ('tp', 'fp'):
                    DB_STATE["triage_decisions"][alert_id] = {
                        'verdict':        verdict,
                        'triaged_at':     datetime.now().timestamp(),
                        'alert_raw_time': float(payload.get('alert_raw_time', 0)),
                    }
                else:
                    return self._send_json(400, {"error": "Invalid verdict"})

                save_db()
                self._send_json(200, {"status": "ok"})
            except Exception as e:
                print(f"[-] Triage POST error: {e}")
                self._send_json(400, {"error": str(e)})
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == '/health':
            return self._send_response(200, 'text/plain', b'OK')

        if self.path == '/login':
            return self._send_html(200, LOGIN_PAGE)

        if not self._require_auth():
            return

        if self.path == '/':
            self._send_html(200, HTML_PAGE)
            
        elif self.path == '/api/alerts':
            self._send_json(200, fetch_parsed_alerts())

        elif self.path == '/api/triage':
            self._send_json(200, DB_STATE["triage_decisions"])

        elif self.path == '/api/stats':
            data = fetch_parsed_alerts()
            t_tp = sum(1 for d in DB_STATE["triage_decisions"].values() if d['verdict'] == 'tp')
            t_fp = sum(1 for d in DB_STATE["triage_decisions"].values() if d['verdict'] == 'fp')
            tot = t_tp + t_fp
            
            self._send_json(200, {
                "total":          len(data),
                "triaged_tp":     t_tp,
                "triaged_fp":     t_fp,
                "fpr":            round(t_fp / tot * 100, 2) if tot else 0,
                "pending":        len(data) - tot,
                "unique_ips":     len(set(a['ip'] for a in data)),
                "generated":      datetime.now(timezone.utc).isoformat() + 'Z',
            })
        else:
            self.send_error(404)

# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == '__main__':
    load_db()
    PORT, IP = CONFIG['port'], CONFIG['dashboard_ip']
    server = HTTPServer((CONFIG['bind_address'], PORT), SOCHandler)
    
    print('\n' + '='*62)
    print('  [ ANAOS SOC ENGINE ] — ANALYST TRIAGE MODE')
    print(f'  Dashboard   -> http://{IP}:{PORT}/')
    print(f'  DB File     -> {CONFIG["db_file"]} (Persisted)')
    print('='*62 + '\n')
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[!] Shutting down SOC engine...')
        server.server_close()
