# -*- coding: utf-8 -*-
"""
OpenVPN Telegram Monitor Bot (TLS-crypt v2 edition; autodetect + Telegraph fallback + robust input flags)
База: функционал из XSFORM/OpenVpn-scramble-xormask (2025-10-01) +
      поддержка tls-crypt-v2 при генерации/удалении ключей + авто-детект.

- Авто-детект tls-crypt-v2 (server.conf и server/server.conf)
- Поиск клиентского tls-crypt-v2 ключа: per-client -> crypt2.key -> crypt.key -> tls-crypt-v2-client.key -> первый валидный *.key
- Telegraph fallback: если Telegra.ph недоступен, списки выводятся прямо в чат.
- Надёжная обработка числового ввода: флаги ожидания дублируются в user_data и chat_data.
- Исправлены кнопки: Удалить/Отправить/Вкл/Откл/Обновить адрес/Помощь/Лог.
"""

import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict
from html import escape
import glob
import json
import traceback
import re
import requests
import shutil
import socket

from OpenSSL import crypto
import pytz

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes,
    MessageHandler, filters
)

from config import TOKEN, ADMIN_ID

BACKUP_AVAILABLE = True
try:
    from backup_restore import (
        create_backup as br_create_backup,
        apply_restore,
        BACKUP_OUTPUT_DIR,
        MANIFEST_NAME
    )
except Exception:
    BACKUP_AVAILABLE = False
    BACKUP_OUTPUT_DIR = ""
    MANIFEST_NAME = "manifest.json"
    def br_create_backup():
        raise RuntimeError("backup_restore.py не найден")

BOT_VERSION = "2025-10-16-tlsv2-autodetect+tg-fallback+robust-input"
UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/XSFORM/update_bot/main/openvpn_monitor_bot.py"
SIMPLE_UPDATE_CMD = (
    "curl -L -o /root/monitor_bot/openvpn_monitor_bot.py "
    f"{UPDATE_SOURCE_URL} && systemctl restart vpn_bot.service"
)

TELEGRAPH_TOKEN_FILE = "/root/monitor_bot/telegraph_token.txt"
TELEGRAPH_SHORT_NAME = "vpn-bot"
TELEGRAPH_AUTHOR = "VPN Bot"

KEYS_DIR = "/root"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
STATUS_LOG = "/var/log/openvpn/status.log"
CCD_DIR = "/etc/openvpn/ccd"

TLS_CRYPT_V2_DIR = "/etc/openvpn/keys-v2"
TLS_CRYPT_V2_DEFAULTS = [
    os.path.join(TLS_CRYPT_V2_DIR, "crypt2.key"),
    os.path.join(TLS_CRYPT_V2_DIR, "crypt.key"),
    "/etc/openvpn/tls-crypt-v2-client.key",
    "/etc/openvpn/server/tls-crypt-v2-client.key",
]
TLS_V2_HEADER = "BEGIN OpenVPN tls-crypt-v2 client key"

SEND_NEW_OVPN_ON_RENEW = False
TM_TZ = pytz.timezone("Asia/Ashgabat")

MGMT_SOCKET = "/var/run/openvpn.sock"
MANAGEMENT_HOST = "127.0.0.1"
MANAGEMENT_PORT = 7505
MANAGEMENT_TIMEOUT = 3

MIN_ONLINE_ALERT = 15
ALERT_INTERVAL_SEC = 300
last_alert_time = 0
clients_last_online = set()

TRAFFIC_DB_PATH = "/root/monitor_bot/traffic_usage.json"
traffic_usage: Dict[str, Dict[str, int]] = {}
_last_session_state = {}
_last_traffic_save_time = 0
TRAFFIC_SAVE_INTERVAL = 60

CLIENT_META_PATH = "/root/monitor_bot/clients_meta.json"
client_meta: Dict[str, Dict[str, str]] = {}

ENFORCE_INTERVAL_SECONDS = 43200  # 12 часов
PAGE_SIZE_KEYS = 40

MENU_MESSAGE_ID = None
MENU_CHAT_ID = None

_notified_expiry: Dict[str, str] = {}
UPCOMING_EXPIRY_DAYS = 1

_nat_num_re = re.compile(r'(\d+)')
def _natural_key(s: str):
    return [int(x) if x.isdigit() else x.lower() for x in _nat_num_re.split(s)]
def natural_sorted(seq: List[str]) -> List[str]:
    return sorted(seq, key=_natural_key)

def _tz_now_str():
    return datetime.now(pytz.utc).astimezone(TM_TZ).strftime("%Y-%m-%d %H:%M:%S")

def locate_backup(fname: str) -> Optional[str]:
    if fname.startswith("/"):
        if os.path.isfile(fname):
            return fname
    try:
        if 'BACKUP_OUTPUT_DIR' in globals() and BACKUP_OUTPUT_DIR:
            p = os.path.join(BACKUP_OUTPUT_DIR, fname)
            if os.path.isfile(p):
                return p
    except Exception:
        pass
    for base in ("/root", "/root/backups"):
        p = os.path.join(base, fname)
        if os.path.isfile(p):
            return p
    return None

# ------------------ Надёжные флаги ожидания (user_data + chat_data) ------------------
def set_flag(context: ContextTypes.DEFAULT_TYPE, key: str, value=True):
    context.user_data[key] = value
    context.chat_data[key] = value

def get_flag(context: ContextTypes.DEFAULT_TYPE, key: str) -> bool:
    return bool(context.user_data.get(key) or context.chat_data.get(key))

def clear_flag(context: ContextTypes.DEFAULT_TYPE, key: str):
    context.user_data.pop(key, None)
    context.chat_data.pop(key, None)

def set_store(context: ContextTypes.DEFAULT_TYPE, key: str, value):
    context.user_data[key] = value
    context.chat_data[key] = value

def get_store(context: ContextTypes.DEFAULT_TYPE, key: str, default=None):
    return context.user_data.get(key, context.chat_data.get(key, default))

def clear_store(context: ContextTypes.DEFAULT_TYPE, *keys):
    for k in keys:
        context.user_data.pop(k, None)
        context.chat_data.pop(k, None)

# ------------------ Логические сроки ------------------
def load_client_meta():
    global client_meta
    try:
        if os.path.exists(CLIENT_META_PATH):
            with open(CLIENT_META_PATH, "r") as f:
                client_meta = json.load(f)
        else:
            client_meta = {}
    except Exception as e:
        print(f"[{_tz_now_str()}] [meta] load error: {e}")
        client_meta = {}

def save_client_meta():
    try:
        tmp = CLIENT_META_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(client_meta, f)
        os.replace(tmp, CLIENT_META_PATH)
    except Exception as e:
        print(f"[{_tz_now_str()}] [meta] save error: {e}")

def set_client_expiry_days_from_now(name: str, days: int) -> str:
    if days < 1:
        days = 1
    dt = datetime.utcnow() + timedelta(days=days)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    client_meta.setdefault(name, {})["expire"] = iso
    save_client_meta()
    unblock_client_ccd(name)
    return iso

def get_client_expiry(name: str) -> Tuple[Optional[str], Optional[int]]:
    data = client_meta.get(name)
    if not data:
        return None, None
    iso = data.get("expire")
    if not iso:
        return None, None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        return iso, (dt - datetime.utcnow()).days
    except Exception:
        return iso, None

def enforce_client_expiries():
    now = datetime.utcnow()
    changed = False
    for name, data in list(client_meta.items()):
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        if now > dt and not is_client_ccd_disabled(name):
            block_client_ccd(name)
            disconnect_client_sessions(name)
            changed = True
    if changed:
        print(f"[{_tz_now_str()}] [meta] enforced expiries")

def check_and_notify_expiring(bot):
    if not client_meta:
        return
    now = datetime.utcnow()
    for name, data in client_meta.items():
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        days_left = (dt - now).days
        if days_left == UPCOMING_EXPIRY_DAYS and not is_client_ccd_disabled(name):
            if _notified_expiry.get(name) == iso:
                continue
            try:
                bot.send_message(
                    ADMIN_ID,
                    f"\u26A0\ufe0f Клиент {name} истекает через {days_left} день (до {iso}). Продли: \u231B Обновить ключ."
                )
                _notified_expiry[name] = iso
            except Exception as e:
                print(f"[{_tz_now_str()}] [notify_expiring] fail {name}: {e}")
        elif _notified_expiry.get(name) and _notified_expiry.get(name) != iso and days_left >= 0:
            _notified_expiry.pop(name, None)

# ------------------ Management ------------------
def _mgmt_tcp_command(cmd: str) -> str:
    data = b""
    with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), MANAGEMENT_TIMEOUT) as s:
        s.settimeout(MANAGEMENT_TIMEOUT)
        try: data += s.recv(4096)
        except Exception: pass
        s.sendall((cmd.strip() + "\n").encode())
        time.sleep(0.15)
        try:
            while True:
                chunk = s.recv(65535)
                if not chunk: break
                data += chunk
                if len(chunk) < 65535: break
        except Exception: pass
        try: s.sendall(b"quit\n")
        except Exception: pass
    return data.decode(errors="ignore")

def disconnect_client_sessions(client_name: str) -> bool:
    try:
        out = _mgmt_tcp_command(f"client-kill {client_name}")
        if out:
            print(f"[{_tz_now_str()}] [mgmt] client-kill {client_name} -> {out.strip()[:120]}")
            return True
    except Exception:
        pass
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            print(f"[{_tz_now_str()}] [mgmt] unix kill {client_name}")
            return True
        except Exception as e:
            print(f"[{_tz_now_str()}] [mgmt] unix kill failed {client_name}: {e}")
    return False

# ------------------ Update helpers ------------------
async def show_update_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        f"<b>Команда обновления:</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML"
    )

async def send_simple_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("\U0001F4CB Копия", callback_data="copy_update_cmd")]])
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"<b>Команда обновления (версия {BOT_VERSION}):</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML",
        reply_markup=kb
    )

async def resend_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer("Отправлено")
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"<code>{SIMPLE_UPDATE_CMD}</code>", parse_mode="HTML")

# ------------------ Helpers ------------------
def get_ovpn_files():
    return [f for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]

def is_client_ccd_disabled(client_name):
    p = os.path.join(CCD_DIR, client_name)
    if not os.path.exists(p): return False
    try:
        with open(p, "r") as f:
            return "disable" in f.read().lower()
    except:
        return False

def block_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("disable\n")
    disconnect_client_sessions(client_name)

def unblock_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("enable\n")

def split_message(text, max_length=4000):
    lines = text.split('\n')
    out, cur = [], ""
    for line in lines:
        if len(cur) + len(line) + 1 <= max_length:
            cur += line + "\n"
        else:
            out.append(cur); cur = line + "\n"
    if cur: out.append(cur)
    return out

def format_clients_by_certs():
    cert_dir = f"{EASYRSA_DIR}/pki/issued/"
    if not os.path.isdir(cert_dir):
        return "<b>Список клиентов:</b>\n\nКаталог issued отсутствует."
    certs = [f for f in os.listdir(cert_dir) if f.endswith(".crt")]
    certs = sorted(certs, key=lambda x: _natural_key(x[:-4]))
    res = "<b>Список клиентов (по сертификатам):</b>\n\n"
    idx = 1
    for f in certs:
        name = f[:-4]
        if name.startswith("server_"):
            continue
        mark = "\u26D4" if is_client_ccd_disabled(name) else "\U0001F7E2"
        res += f"{idx}. {mark} <b>{name}</b>\n"
        idx += 1
    if idx == 1:
        res += "Нет выданных сертификатов."
    return res

def parse_remote_proto_from_ovpn(path: str):
    remote = ""; proto = ""
    try:
        with open(path, "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("remote "):
                    parts = ls.split()
                    if len(parts) >= 3:
                        remote = parts[2]
                elif ls.startswith("proto "):
                    proto = ls.split()[1]
                if remote and proto:
                    break
    except:
        pass
    return f"{remote}:{proto}" if (remote or proto) else ""

def get_cert_days_left(client_name: str) -> Optional[int]:
    cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if not os.path.exists(cert_path): return None
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        not_after = cert.get_notAfter().decode("ascii")
        expiry_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
        return (expiry_dt - datetime.utcnow()).days
    except Exception:
        return None

def gather_key_metadata():
    rows = []
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    for f in files:
        name = f[:-5]
        days = get_cert_days_left(name)
        days_str = str(days) if days is not None else "-"
        ovpn_path = os.path.join(KEYS_DIR, f)
        cfg = parse_remote_proto_from_ovpn(ovpn_path)
        crt_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        ctime = "-"
        try:
            path_for_time = crt_path if os.path.exists(crt_path) else ovpn_path
            ts = os.path.getmtime(path_for_time)
            ctime = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        except:
            pass
        rows.append({"name": name, "days": days_str, "cfg": cfg, "created": ctime})
    return rows

def build_keys_table_text(rows: List[Dict]):
    if not rows: return "Нет ключей."
    name_w = max([len(r["name"]) for r in rows] + [4])
    cfg_w = max([len(r["cfg"]) for r in rows] + [6])
    days_w = max([len(r["days"]) for r in rows] + [4])
    header = f"N | {'Имя'.ljust(name_w)} | {'СерДн'.ljust(days_w)} | {'Конфиг'.ljust(cfg_w)} | Создан"
    lines = [header]
    for i, r in enumerate(rows, 1):
        lines.append(f"{i} | {r['name'].ljust(name_w)} | {r['days'].ljust(days_w)} | {r['cfg'].ljust(cfg_w)} | {r['created']}")
    return "\n".join(lines)

# ------------------ Telegraph + fallback ------------------
def get_telegraph_token() -> Optional[str]:
    try:
        if os.path.exists(TELEGRAPH_TOKEN_FILE):
            with open(TELEGRAPH_TOKEN_FILE, "r") as f:
                tok = f.read().strip()
                if tok: return tok
        resp = requests.post("https://api.telegra.ph/createAccount",
                             data={"short_name": TELEGRAPH_SHORT_NAME,"author_name": TELEGRAPH_AUTHOR},
                             timeout=10)
        data = resp.json()
        token = data.get("result", {}).get("access_token")
        if token:
            os.makedirs(os.path.dirname(TELEGRAPH_TOKEN_FILE), exist_ok=True)
            with open(TELEGRAPH_TOKEN_FILE, "w") as f:
                f.write(token)
            return token
    except Exception as e:
        print(f"[{_tz_now_str()}] [telegraph] token error: {e}")
    return None

def create_telegraph_pre_page(title: str, text: str) -> Optional[str]:
    token = get_telegraph_token()
    if not token: return None
    content_nodes = json.dumps([{"tag": "pre", "children": [text]}], ensure_ascii=False)
    try:
        resp = requests.post("https://api.telegra.ph/createPage", data={
            "access_token": token,
            "title": title,
            "author_name": TELEGRAPH_AUTHOR,
            "content": content_nodes,
            "return_content": "false"
        }, timeout=15)
        data = resp.json()
        return data.get("result", {}).get("url")
    except Exception as e:
        print(f"[{_tz_now_str()}] [telegraph] create page error: {e}")
        return None

def _fallback_names_page(names: List[str], title: str, caption: str) -> str:
    names = natural_sorted(names)
    lines = [f"{title}", caption, ""]
    for i, n in enumerate(names, 1):
        lines.append(f"{i}. {n}")
    return "\n".join(lines)

def create_keys_detailed_page():
    rows = gather_key_metadata()
    if not rows: return None
    text = "Полный список ключей (СерДн = остаток по сертификату, не логический срок)\n\n" + build_keys_table_text(rows)
    return create_telegraph_pre_page("Список ключей", text)

def create_names_telegraph_page(names: List[str], title: str, caption: str) -> Tuple[Optional[str], Optional[str]]:
    if not names: return None, None
    url = create_telegraph_pre_page(title, "\n".join([caption] + [f"{i}. {n}" for i, n in enumerate(natural_sorted(names), 1)]))
    fallback = _fallback_names_page(names, title, caption) if not url else None
    return url, fallback

# ------------------ TLS-crypt-v2 detect/search ------------------
def _detect_tls_sig() -> int:
    candidates = [
        os.path.join(OPENVPN_DIR, "server.conf"),
        os.path.join(OPENVPN_DIR, "server", "server.conf"),
    ]
    for p in candidates:
        try:
            if os.path.exists(p):
                with open(p, "r", errors="ignore") as f:
                    conf = f.read().lower()
                if "tls-crypt-v2" in conf:
                    print(f"[{_tz_now_str()}] [tls] detected tls-crypt-v2 in {p}")
                    return 3
                if "tls-crypt" in conf:
                    print(f"[{_tz_now_str()}] [tls] detected tls-crypt in {p}")
                    return 1
                if "tls-auth" in conf:
                    print(f"[{_tz_now_str()}] [tls] detected tls-auth in {p}")
                    return 2
        except Exception as e:
            print(f"[{_tz_now_str()}] [tls] read server.conf failed {p}: {e}")
    print(f"[{_tz_now_str()}] [tls] no tls-* signature detected")
    return 0

def _file_contains_tlsv2_key(path: str) -> bool:
    try:
        with open(path, "r", errors="ignore") as f:
            head = f.read(200)
        return TLS_V2_HEADER in head
    except Exception:
        return False

def _tlsv2_client_key_path_for(name: str) -> Optional[str]:
    candidates = [os.path.join(TLS_CRYPT_V2_DIR, f"{name}.key")] + TLS_CRYPT_V2_DEFAULTS
    for p in candidates:
        if os.path.exists(p) and _file_contains_tlsv2_key(p):
            print(f"[{_tz_now_str()}] [tlsv2] using client key: {p}")
            return p
    try:
        if os.path.isdir(TLS_CRYPT_V2_DIR):
            for fname in sorted(os.listdir(TLS_CRYPT_V2_DIR)):
                if fname.endswith(".key"):
                    p = os.path.join(TLS_CRYPT_V2_DIR, fname)
                    if _file_contains_tlsv2_key(p):
                        print(f"[{_tz_now_str()}] [tlsv2] fallback client key: {p}")
                        return p
    except Exception as e:
        print(f"[{_tz_now_str()}] [tlsv2] scan keys-v2 failed: {e}")
    print(f"[{_tz_now_str()}] [tlsv2] client key not found in any known location")
    return None

# ------------------ Генерация .ovpn ------------------
def extract_pem_cert(cert_path: str) -> str:
    with open(cert_path, "r") as f:
        lines = f.read().splitlines()
    in_pem = False
    out = []
    for line in lines:
        if "-----BEGIN CERTIFICATE-----" in line:
            in_pem = True
        if in_pem:
            out.append(line)
        if "-----END CERTIFICATE-----" in line:
            break
    return "\n".join(out).strip()

def generate_ovpn_for_client(
    client_name,
    output_dir=KEYS_DIR,
    template_path=f"{OPENVPN_DIR}/client-template.txt",
    ca_path=f"{EASYRSA_DIR}/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path=f"{OPENVPN_DIR}/tls-crypt.key",
    tls_auth_path=f"{OPENVPN_DIR}/tls-auth.key",
    server_conf_path=None
):
    if cert_path is None:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"
    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")

    TLS_SIG = _detect_tls_sig()

    with open(template_path, "r") as f:
        template_content = f.read().rstrip()
    with open(ca_path, "r") as f:
        ca_content = f.read().strip()
    cert_content = extract_pem_cert(cert_path)
    with open(key_path, "r") as f:
        key_content = f.read().strip()

    content = (template_content + "\n"
               "<ca>\n" + ca_content + "\n</ca>\n"
               "<cert>\n" + cert_content + "\n</cert>\n"
               "<key>\n" + key_content + "\n</key>\n")

    if TLS_SIG == 3:
        v2_path = _tlsv2_client_key_path_for(client_name)
        if v2_path and os.path.exists(v2_path):
            with open(v2_path, "r") as f:
                tls_v2_content = f.read().strip()
            content += "<tls-crypt-v2>\n" + tls_v2_content + "\n</tls-crypt-v2>\n"
        else:
            print(f"[{_tz_now_str()}] [tlsv2] WARNING: no client key found for {client_name} — .ovpn без <tls-crypt-v2>")
    elif TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read().strip()
        content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read().strip()
        content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(content)
    print(f"[{_tz_now_str()}] [ovpn] written {ovpn_file} (TLS_SIG={TLS_SIG})")
    return ovpn_file

# ------------------ Создание ключей ------------------
async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Шаг 1: Имя
    if get_flag(context, 'await_key_name'):
        key_name = update.message.text.strip()
        if not key_name:
            await update.message.reply_text("Имя пустое. Введите имя:")
            return
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text("Такой клиент существует, введите другое имя.")
            return
        set_store(context, 'new_key_name', key_name)
        clear_flag(context, 'await_key_name')
        set_flag(context, 'await_key_expiry', True)
        await update.message.reply_text("Введите логический срок (дней, по умолчанию 30):")
        return

    # Шаг 2: Срок
    if get_flag(context, 'await_key_expiry'):
        try:
            days = int(update.message.text.strip())
            if days < 1: raise ValueError
        except:
            days = 30
        set_store(context, 'new_key_expiry', days)
        clear_flag(context, 'await_key_expiry')
        set_flag(context, 'await_key_quantity', True)
        await update.message.reply_text("Введите количество ключей (по умолчанию 1):")
        return

    # Шаг 3: Количество
    if get_flag(context, 'await_key_quantity'):
        try:
            qty = int(update.message.text.strip())
            if qty < 1: raise ValueError
        except:
            qty = 1
        if qty > 100:
            await update.message.reply_text("Слишком много. Максимум 100. Введите снова:")
            return
        base = get_store(context, 'new_key_name')
        days = get_store(context, 'new_key_expiry', 30)

        names = [base] if qty == 1 else [base] + [f"{base}{i}" for i in range(2, qty + 1)]
        collisions = [n for n in names if os.path.exists(os.path.join(KEYS_DIR, f"{n}.ovpn"))]
        if collisions:
            await update.message.reply_text(
                "Конфликт имён (существуют): " + ", ".join(collisions) +
                "\nВведите другое базовое имя /start → Создать ключ"
            )
            clear_store(context, 'new_key_name', 'new_key_expiry')
            clear_flag(context, 'await_key_quantity')
            return

        created, errors = [], []
        for n in names:
            try:
                subprocess.run(
                    f"EASYRSA_CERT_EXPIRE=3650 {EASYRSA_DIR}/easyrsa --batch build-client-full {n} nopass",
                    shell=True, check=True, cwd=EASYRSA_DIR
                )
                ovpn_path = generate_ovpn_for_client(n)
                iso = set_client_expiry_days_from_now(n, days)
                created.append((n, ovpn_path, iso))
            except subprocess.CalledProcessError as e:
                errors.append(f"{n}: {e}")
            except Exception as e:
                errors.append(f"{n}: {e}")

        if created:
            await update.message.reply_text(f"Создано ключей: {len(created)} (срок ~{days} дн)", parse_mode="HTML")
            for (n, path, iso) in created:
                try:
                    await update.message.reply_text(f"{n}: до {iso}\n{path}")
                    with open(path, "rb") as f:
                        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=f"{n}.ovpn")
                except Exception as e:
                    await update.message.reply_text(f"Ошибка отправки {n}: {e}")
        if errors:
            err_txt = "\n".join(errors[:10])
            if len(errors) > 10: err_txt += f"\n... ещё {len(errors)-10}"
            await update.message.reply_text(f"Ошибки:\n{err_txt}")

        clear_store(context, 'new_key_name', 'new_key_expiry')
        clear_flag(context, 'await_key_quantity')
        return

# ------------------ Renew (логический) ------------------
async def renew_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    order = [r["name"] for r in rows]
    set_store(context, 'renew_keys_order', order)
    set_flag(context, 'await_renew_number', True)
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]])
    text = ("<b>Установить новый логический срок</b>\n"
            "Открой список и введи НОМЕР клиента:\n"
            f"<a href=\"{url}\">Список (Telegraph)</a>\n\nПример: 5")
    await safe_edit_text(q, context, text, parse_mode="HTML", reply_markup=kb)

async def process_renew_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_renew_number'): return
    text = update.message.text.strip()
    if not re.fullmatch(r"\d+", text):
        await update.message.reply_text("Нужно ввести один номер клиента.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    idx = int(text)
    order: List[str] = get_store(context, 'renew_keys_order', [])
    if not order:
        await update.message.reply_text("Список потерян. Начните заново.")
        clear_flag(context, 'await_renew_number'); return
    if idx < 1 or idx > len(order):
        await update.message.reply_text(f"Номер вне диапазона 1..{len(order)}.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    key_name = order[idx - 1]
    set_store(context, 'renew_key_name', key_name)
    clear_flag(context, 'await_renew_number')
    set_flag(context, 'await_renew_expiry', True)
    await update.message.reply_text(f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    clear_flag(context, 'await_renew_number')
    clear_flag(context, 'await_renew_expiry')
    clear_store(context, 'renew_keys_order', 'renew_key_name')
    await safe_edit_text(q, context, "Продление отменено.")

async def renew_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    data = q.data
    key_name = data.split('_', 1)[1]
    set_store(context, 'renew_key_name', key_name)
    set_flag(context, 'await_renew_expiry', True)
    await safe_edit_text(q, context, f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_renew_expiry'): return
    key_name = get_store(context, 'renew_key_name')
    try:
        days = int(update.message.text.strip())
        if days < 1: raise ValueError
    except Exception:
        await update.message.reply_text("Некорректное число дней."); return
    iso = set_client_expiry_days_from_now(key_name, days)
    await update.message.reply_text(f"Логический срок для {key_name} установлен до: {iso} (~{days} дн). Клиент разблокирован.")
    clear_flag(context, 'await_renew_expiry')
    clear_store(context, 'renew_key_name')

# ------------------ Лог ------------------
def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    log_text = get_status_log_tail()
    safe = _html_escape(log_text)
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{safe}</pre>")
    await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
    for m in msgs[1:]:
        await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

# ------------------ Backup / Restore UI ------------------
def list_backups() -> List[str]:
    return sorted([os.path.basename(p) for p in glob.glob("/root/openvpn_full_backup_*.tar.gz")], reverse=True)

async def perform_backup_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not BACKUP_AVAILABLE:
        await safe_edit_text(update.callback_query, context, "Функция backup недоступна (нет backup_restore.py)."); return
    try:
        path = create_backup_in_root_excluding_archives()
        size = os.path.getsize(path)
        txt = f"\U0001F4E6 Бэкап создан: <code>{os.path.basename(path)}</code>\nРазмер: {size/1024/1024:.2f} MB"
        q = update.callback_query
        await safe_edit_text(q, context, txt, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F4E4 Отправить", callback_data=f"backup_send_{os.path.basename(path)}")],
            [InlineKeyboardButton("\U0001F4E6 Список", callback_data="backup_list")],
        ]))
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка бэкапа: {e}")

async def send_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    with open(full, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=fname)
    await safe_edit_text(update.callback_query, context, "Отправлен.")

async def show_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bl = list_backups()
    if not bl:
        await safe_edit_text(update.callback_query, context, "Бэкапов нет."); return
    kb = [[InlineKeyboardButton(b, callback_data=f"backup_info_{b}")] for b in bl[:15]]
    await safe_edit_text(update.callback_query, context, "Список бэкапов:", reply_markup=InlineKeyboardMarkup(kb))

async def show_backup_info(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    if not BACKUP_AVAILABLE:
        await safe_edit_text(update.callback_query, context, "Нет расширенной информации (backup_restore.py отсутствует)."); return
    full = os.path.join("/root", fname)
    staging = f"/tmp/info_{int(time.time())}"
    os.makedirs(staging, exist_ok=True)
    try:
        import tarfile
        with tarfile.open(full, "r:gz") as tar:
            tar.extractall(staging)
        manifest_path = os.path.join(staging, MANIFEST_NAME)
        if not os.path.exists(manifest_path):
            await safe_edit_text(update.callback_query, context, "manifest.json отсутствует."); return
        with open(manifest_path, "r") as f:
            m = json.load(f)
        clients = m.get("openvpn_pki", {}).get("clients", [])
        v_count = sum(1 for c in clients if c.get("status") == "V")
        r_count = sum(1 for c in clients if c.get("status") == "R")
        txt = (f"<b>{fname}</b>\nСоздан: {m.get('created_at')}\n"
               f"Файлов: {len(m.get('files', []))}\n"
               f"Клиентов V: {v_count} / R: {r_count}\nПоказать diff?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F9EA Diff", callback_data=f"restore_dry_{fname}")],
            [InlineKeyboardButton("\U0001F4E4 Отправить", callback_data=f"backup_send_{fname}")],
            [InlineKeyboardButton("\U0001F5D1\ufe0f Удалить", callback_data=f"backup_delete_{fname}")],
        ])
        await safe_edit_text(update.callback_query, context, txt, parse_mode="HTML", reply_markup=kb)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

async def restore_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    if not BACKUP_AVAILABLE:
        await safe_edit_text(update.callback_query, context, "Restore недоступен (нет backup_restore.py)."); return
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден ни в /root, ни в /root/backups.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=True)
        diff = report["diff"]
        def lim(lst):
            return lst[:6] + [f"... ещё {len(lst)-6}"] if len(lst) > 6 else lst
        text = (f"<b>Diff {os.path.basename(backup_path)}</b>\n"
                f"Extra: {len(diff['extra'])}\n" + "\n".join(lim(diff['extra'])) + "\n\n"
                f"Missing: {len(diff['missing'])}\n" + "\n".join(lim(diff['missing'])) + "\n\n"
                f"Changed: {len(diff['changed'])}\n" + "\n".join(lim(diff['changed'])) + "\n\n"
                "Применить restore?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("\u26A0\ufe0f Применить", callback_data=f"restore_apply_{fname}")],
            [InlineKeyboardButton("\u2B05\ufe0f Назад", callback_data=f"backup_info_{fname}")]
        ])
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML", reply_markup=kb)
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка dry-run: {e}", parse_mode="HTML")

async def restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    if not BACKUP_AVAILABLE:
        await safe_edit_text(update.callback_query, context, "Restore недоступен (нет backup_restore.py)."); return
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден ни в BACKUP_OUTPUT_DIR, ни в /root, ни в /root/backups.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=False)
        diff = report["diff"]
        text = (f"<b>Restore:</b> {os.path.basename(backup_path)}\n"
                f"Удалено extra: {len(diff['extra'])}\n"
                f"Missing: {len(diff['missing'])}\n"
                f"Changed: {len(diff['changed'])}\n"
                f"CRL: {report.get('crl_action')}\n"
                f"OpenVPN restart: {report.get('service_restart')}")
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    except Exception as e:
        tb = traceback.format_exc()
        await safe_edit_text(update.callback_query, context, f"Ошибка restore: {e}\n{tb[-400:]}", parse_mode="HTML")

async def backup_delete_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"backup_delete_confirm_{fname}")],
        [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
    ])
    await safe_edit_text(update.callback_query, context, f"Удалить бэкап <b>{fname}</b>?", parse_mode="HTML", reply_markup=kb)

async def backup_delete_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    try:
        if os.path.exists(full):
            os.remove(full)
            await safe_edit_text(update.callback_query, context, "🗑️ Бэкап удалён.")
            await show_backup_list(update, context)
        else:
            await safe_edit_text(update.callback_query, context, "Файл не найден.")
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка удаления: {e}")

async def backup_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🆕 Создать бэкап", callback_data="backup_create")],
        [InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")],
    ])
    await safe_edit_text(q, context, "Меню бэкапов:", reply_markup=kb)

async def restore_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")]])
    await safe_edit_text(q, context, "Восстановление: выбери бэкап → Diff → Применить.", reply_markup=kb)

# ------------------ Трафик ------------------
def load_traffic_db():
    global traffic_usage
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            with open(TRAFFIC_DB_PATH, "r") as f:
                raw = json.load(f)
            migrated = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    migrated[k] = {'rx': int(v.get('rx', 0)), 'tx': int(v.get('tx', 0))}
            traffic_usage = migrated
        else:
            traffic_usage = {}
    except Exception as e:
        print(f"[{_tz_now_str()}] [traffic] load error: {e}")
        traffic_usage = {}

def save_traffic_db(force=False):
    global _last_traffic_save_time
    now = time.time()
    if not force and now - _last_traffic_save_time < TRAFFIC_SAVE_INTERVAL: return
    try:
        tmp = TRAFFIC_DB_PATH + ".tmp"
        with open(tmp, "w") as f: json.dump(traffic_usage, f)
        os.replace(tmp, TRAFFIC_DB_PATH)
        _last_traffic_save_time = now
    except Exception as e:
        print(f"[{_tz_now_str()}] [traffic] save error: {e}")

def update_traffic_from_status(clients):
    global traffic_usage, _last_session_state
    changed = False
    for c in clients:
        name = c['name']
        try:
            recv = int(c.get('bytes_recv', 0))
            sent = int(c.get('bytes_sent', 0))
        except:
            continue
        connected_since = c.get('connected_since', '')
        prev = _last_session_state.get(name)
        if name not in traffic_usage:
            traffic_usage[name] = {'rx': 0, 'tx': 0}
        if prev is None or prev['connected_since'] != connected_since:
            _last_session_state[name] = {'connected_since': connected_since, 'rx': recv, 'tx': sent}
            continue
        delta_rx = recv - prev['rx']; delta_tx = sent - prev['tx']
        if delta_rx > 0:
            traffic_usage[name]['rx'] += delta_rx; prev['rx'] = recv; changed = True
        else:
            prev['rx'] = recv
        if delta_tx > 0:
            traffic_usage[name]['tx'] += delta_tx; prev['tx'] = sent; changed = True
        else:
            prev['tx'] = sent
    if changed: save_traffic_db()

def clear_traffic_stats():
    global traffic_usage, _last_session_state
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            subprocess.run(f"cp {TRAFFIC_DB_PATH} {TRAFFIC_DB_PATH}.bak_{ts}", shell=True)
    except: pass
    traffic_usage = {}; _last_session_state = {}
    save_traffic_db(force=True)

def build_traffic_report():
    if not traffic_usage:
        return "<b>Трафик:</b>\nНет данных."
    items = sorted(traffic_usage.items(), key=lambda x: x[1]['rx'] + x[1]['tx'], reverse=True)
    lines = ["<b>Использование трафика:</b>"]
    for name, val in items:
        total = val['rx'] + val['tx']
        lines.append(f"• {name}: {total/1024/1024/1024:.2f} GB")
    return "\n".join(lines)

# ------------------ Monitoring loop ------------------
async def check_new_connections(app: Application):
    import asyncio
    global clients_last_online, last_alert_time
    if not hasattr(check_new_connections, "_last_enforce"):
        check_new_connections._last_enforce = 0
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            update_traffic_from_status(clients)
            now_t = time.time()
            if now_t - check_new_connections._last_enforce > ENFORCE_INTERVAL_SECONDS:
                enforce_client_expiries()
                check_and_notify_expiring(app.bot)
                check_new_connections._last_enforce = now_t
            online_count = len(online_names)
            total_keys = len(get_ovpn_files())
            now = time.time()
            if online_count == 0 and total_keys > 0:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, "❌ Все клиенты оффлайн!", parse_mode="HTML")
                    last_alert_time = now
            elif 0 < online_count < MIN_ONLINE_ALERT:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, f"⚠️ Онлайн мало: {online_count}/{total_keys}", parse_mode="HTML")
                    last_alert_time = now
            else:
                if online_count >= MIN_ONLINE_ALERT:
                    last_alert_time = 0
            clients_last_online = set(online_names)
            await asyncio.sleep(10)
        except Exception as e:
            print(f"[{_tz_now_str()}] [monitor] {e}")
            await asyncio.sleep(10)

def parse_openvpn_status(status_path=STATUS_LOG):
    clients = []; online_names = set(); tunnel_ips = {}
    try:
        with open(status_path, "r") as f:
            lines = f.readlines()
        client_list_section = False
        routing_table_section = False
        for line in lines:
            line_s = line.strip()
            if line_s.startswith("OpenVPN CLIENT LIST"):
                client_list_section = True; continue
            if client_list_section and line_s.startswith("Common Name,Real Address"):
                continue
            if client_list_section and not line_s:
                client_list_section = False; continue
            if client_list_section and "," in line_s:
                parts = line_s.split(",")
                if len(parts) >= 5:
                    clients.append({
                        "name": parts[0],
                        "ip": parts[1].split(":")[0],
                        "port": parts[1].split(":")[1] if ":" in parts[1] else "",
                        "bytes_recv": parts[2],
                        "bytes_sent": parts[3],
                        "connected_since": parts[4],
                    })
            if line_s.startswith("ROUTING TABLE"):
                routing_table_section = True; continue
            if routing_table_section and line_s.startswith("Virtual Address,Common Name"):
                continue
            if routing_table_section and not line_s:
                routing_table_section = False; continue
            if routing_table_section and "," in line_s:
                parts = line_s.split(",")
                if len(parts) >= 2:
                    tunnel_ips[parts[1]] = parts[0]
                    online_names.add(parts[1])
    except Exception as e:
        print(f"[{_tz_now_str()}] [parse_openvpn_status] {e}")
    return clients, online_names, tunnel_ips

# ------------------ safe_edit_text ------------------
async def safe_edit_text(q, context, text, **kwargs):
    if MENU_MESSAGE_ID and q.message.message_id == MENU_MESSAGE_ID:
        await context.bot.send_message(chat_id=q.message.chat_id, text=text, **kwargs)
    else:
        await q.edit_message_text(text, **kwargs)

# ------------------ Универсальный текстовый ввод (с логами) ------------------
async def universal_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    txt = (update.message.text or "").strip()
    print(f"[text] '{txt}' flags_user={list(context.user_data.keys())} flags_chat={list(context.chat_data.keys())}")

    # 1) Нормальные флаги (если они на месте)
    if get_flag(context, 'await_bulk_delete_numbers'):
        await process_bulk_delete_numbers(update, context); return
    if get_flag(context, 'await_bulk_send_numbers'):
        await process_bulk_send_numbers(update, context); return
    if get_flag(context, 'await_bulk_enable_numbers'):
        await process_bulk_enable_numbers(update, context); return
    if get_flag(context, 'await_bulk_disable_numbers'):
        await process_bulk_disable_numbers(update, context); return
    if get_flag(context, 'await_renew_number'):
        await process_renew_number(update, context); return
    if get_flag(context, 'await_renew_expiry'):
        await renew_key_expiry_handler(update, context); return
    if (get_flag(context, 'await_key_name') or
        get_flag(context, 'await_key_expiry') or
        get_flag(context, 'await_key_quantity')):
        await create_key_handler(update, context); return
    if get_flag(context, 'await_remote_input'):
        await process_remote_input(update, context); return

    # 2) ХЕВРИСТИКА: если флаг потерялся, но есть сохранённые списки и текст похож на выбор,
    #    восстанавливаем флаг на лету и обрабатываем.
    import re as _re

    def _looks_like_selection(s: str) -> bool:
        # Поддержка: all | 1 | 1,2,5 | 3-7 | 1,2,5-9 | смешанные диапазоны
        return bool(_re.fullmatch(r"(all|\d+|\d+(?:[,\s]+\d+)*|\d+-\d+(?:[,\s]+(?:\d+|\d+-\d+))*)", s.strip(), flags=_re.I))

    if _looks_like_selection(txt):
        if get_store(context, 'bulk_delete_keys', []):
            set_flag(context, 'await_bulk_delete_numbers', True)
            await process_bulk_delete_numbers(update, context); return
        if get_store(context, 'bulk_send_keys', []):
            set_flag(context, 'await_bulk_send_numbers', True)
            await process_bulk_send_numbers(update, context); return
        if get_store(context, 'bulk_enable_keys', []):
            set_flag(context, 'await_bulk_enable_numbers', True)
            await process_bulk_enable_numbers(update, context); return
        if get_store(context, 'bulk_disable_keys', []):
            set_flag(context, 'await_bulk_disable_numbers', True)
            await process_bulk_disable_numbers(update, context); return
        if get_store(context, 'renew_keys_order', []):
            set_flag(context, 'await_renew_number', True)
            await process_renew_number(update, context); return

    await update.message.reply_text("Неизвестный ввод. Используй меню или /start.")

# ------------------ HELP / START / Прочие команды ------------------
def get_main_keyboard():
    E = {
        "refresh": "\U0001F501",
        "stats": "\U0001F4CA",
        "tunnel": "\U0001F6E3\ufe0f",
        "traffic": "\U0001F4F6",
        "update": "\U0001F517",
        "cleanup": "\U0001F9F9",
        "remote": "\U0001F310",
        "expiry": "\u23F3",
        "renew": "\u231B",
        "enable": "\u2705",
        "disable": "\u26A0\ufe0f",
        "create": "\u2795",
        "delete": "\U0001F5D1\ufe0f",
        "send": "\U0001F4E4",
        "log": "\U0001F4DC",
        "backup": "\U0001F4E6",
        "restore": "\U0001F504",
        "alert": "\U0001F6A8",
        "help": "\u2753",
        "home": "\U0001F3E0",
    }
    keyboard = [
        [InlineKeyboardButton(f"{E['refresh']} Список клиентов", callback_data='refresh')],
        [InlineKeyboardButton(f"{E['stats']} Статистика", callback_data='stats'),
         InlineKeyboardButton(f"{E['tunnel']} Тунель", callback_data='send_ipp')],
        [InlineKeyboardButton(f"{E['traffic']} Трафик", callback_data='traffic'),
         InlineKeyboardButton(f"{E['update']} Обновление", callback_data='update_info')],
        [InlineKeyboardButton(f"{E['cleanup']} Очистить трафик", callback_data='traffic_clear'),
         InlineKeyboardButton(f"{E['remote']} Обновить адрес", callback_data='update_remote')],
        [InlineKeyboardButton(f"{E['expiry']} Сроки ключей", callback_data='keys_expiry'),
         InlineKeyboardButton(f"{E['renew']} Обновить ключ", callback_data='renew_key')],
        [InlineKeyboardButton(f"{E['enable']} Вкл.клиента", callback_data='bulk_enable_start'),
         InlineKeyboardButton(f"{E['disable']} Откл.клиента", callback_data='bulk_disable_start')],
        [InlineKeyboardButton(f"{E['create']} Создать ключ", callback_data='create_key'),
         InlineKeyboardButton(f"{E['delete']} Удалить ключ", callback_data='bulk_delete_start')],
        [InlineKeyboardButton(f"{E['send']} Отправить ключи", callback_data='bulk_send_start'),
         InlineKeyboardButton(f"{E['log']} Просмотр лога", callback_data='log')],
        [InlineKeyboardButton(f"{E['backup']} Бэкап OpenVPN", callback_data='backup_menu'),
         InlineKeyboardButton(f"{E['restore']} Восстан.бэкап", callback_data='restore_menu')],
        [InlineKeyboardButton(f"{E['alert']} Тревога блокировки", callback_data='block_alert')],
        [InlineKeyboardButton(f"{E['help']} Помощь", callback_data='help'),
         InlineKeyboardButton(f"{E['home']} В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    global MENU_MESSAGE_ID, MENU_CHAT_ID
    kb = get_main_keyboard()
    if MENU_MESSAGE_ID and MENU_CHAT_ID:
        try:
            await context.bot.delete_message(chat_id=MENU_CHAT_ID, message_id=MENU_MESSAGE_ID)
        except: pass
    sent = await update.message.reply_text(f"Добро пожаловать! Версия: {BOT_VERSION}", reply_markup=kb)
    MENU_MESSAGE_ID = sent.message_id; MENU_CHAT_ID = sent.chat.id

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    esc = escape(HELP_TEXT.strip("\n"))
    parts = esc.splitlines()
    LIMIT = 3500
    block, cur_len = [], 0
    for line in parts:
        l = len(line) + 1
        if block and cur_len + l > LIMIT:
            content = "\n".join(block)
            await update.message.reply_text(f"<b>Помощь</b>\n<pre>{content}</pre>", parse_mode="HTML")
            block, cur_len = [line], l
        else:
            block.append(line); cur_len += l
    if block:
        content = "\n".join(block)
        await update.message.reply_text(f"<b>Помощь</b>\n<pre>{content}</pre>", parse_mode="HTML")

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(format_clients_by_certs(), parse_mode="HTML")

async def traffic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    save_traffic_db(force=True)
    await update.message.reply_text(build_traffic_report(), parse_mode="HTML")

async def cmd_backup_now(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    try:
        path = create_backup_in_root_excluding_archives()
        await update.message.reply_text(f"📦 Бэкап: {os.path.basename(path)}")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

async def cmd_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    items = list_backups()
    if not items:
        await update.message.reply_text("Бэкапов нет."); return
    await update.message.reply_text("<b>Бэкапы:</b>\n" + "\n".join(items), parse_mode="HTML")

async def cmd_backup_restore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    if not BACKUP_AVAILABLE:
        await update.message.reply_text("Расширенный restore недоступен (нет backup_restore.py)."); return
    report = apply_restore(path, dry_run=True)
    diff = report["diff"]
    await update.message.reply_text(
        f"Dry-run {fname}:\nExtra={len(diff['extra'])} Missing={len(diff['missing'])} Changed={len(diff['changed'])}\n"
        f"Применить: /backup_restore_apply {fname}"
    )

async def cmd_backup_restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore_apply <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    if not BACKUP_AVAILABLE:
        await update.message.reply_text("Расширенный restore недоступен (нет backup_restore.py)."); return
    report = apply_restore(path, dry_run=False)
    diff = report["diff"]
    await update.message.reply_text(
        f"Restore {fname}:\nExtra удалено: {len(diff['extra'])}\nMissing: {len(diff['missing'])}\nChanged: {len(diff['changed'])}"
    )

# ------------------ Просмотр логических сроков ------------------
async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    names = [f[:-5] for f in files]
    text = "<b>Логические сроки клиентов:</b>\n"
    if not names:
        text += "Нет."
    else:
        rows = []
        for name in names:
            iso, days_left = get_client_expiry(name)
            if iso is None:
                status = "нет срока"
            else:
                if days_left is not None:
                    if days_left < 0: status = f"❌ истёк ({iso})"
                    elif days_left == 0: status = f"⚠️ сегодня ({iso})"
                    else: status = f"{days_left}д (до {iso})"
                else:
                    status = iso
            mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
            rows.append(f"{mark} {name}: {status}")
        text += "\n".join(rows)
    if update.callback_query:
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")

# ------------------ BULK: Delete/Send/Enable/Disable ------------------
async def start_bulk_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    keys_order = [r["name"] for r in rows]
    set_store(context, 'bulk_delete_keys', keys_order)
    set_flag(context, 'await_bulk_delete_numbers', True)
    if url:
        text = ("<b>Удаление ключей</b>\n"
                "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
                f"<a href=\"{url}\">Полный список</a>\n\nОтправьте строку с номерами.")
    else:
        fallback = _fallback_names_page(keys_order, "Удаление ключей", "Список ключей")
        text = ("<b>Удаление ключей</b>\n"
                "Telegraph недоступен — список ниже, вводите номера.\n\n<pre>" + escape(fallback) + "</pre>")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))

async def process_bulk_delete_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_bulk_delete_numbers'): return
    keys_order: List[str] = get_store(context, 'bulk_delete_keys', [])
    if not keys_order:
        await update.message.reply_text("Список потерян. Начните снова.")
        clear_flag(context, 'await_bulk_delete_numbers'); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(keys_order))
    if errs or not idxs:
        msg = "Ошибки:\n" + "\n".join(errs) if errs else "Ничего не выбрано."
        await update.message.reply_text(msg,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))
        return
    selected_names = [keys_order[i - 1] for i in idxs]
    set_store(context, 'bulk_delete_selected', selected_names)
    clear_flag(context, 'await_bulk_delete_numbers')
    preview = "\n".join(selected_names[:25]) + (f"\n... ещё {len(selected_names)-25}" if len(selected_names) > 25 else "")
    await update.message.reply_text(
        f"<b>Удалить ключи ({len(selected_names)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_delete_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
        ])
    )

async def bulk_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = get_store(context, 'bulk_delete_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    revoked, failed = revoke_and_collect(selected)
    crl_status = generate_crl_once()
    for name in revoked:
        remove_client_files(name)
        disconnect_client_sessions(name)
    clear_store(context, 'bulk_delete_selected', 'bulk_delete_keys')
    summary = (f"<b>Удаление завершено</b>\n"
               f"Запрошено: {len(selected)}\nRevoked: {len(revoked)}\nОшибок: {len(failed)}\nCRL: {crl_status}")
    if failed:
        summary += "\n\n<b>Ошибки:</b>\n" + "\n".join(failed[:10])
        if len(failed) > 10: summary += f"\n... ещё {len(failed)-10}"
    await safe_edit_text(q, context, summary, parse_mode="HTML")

async def bulk_delete_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    clear_flag(context, 'await_bulk_delete_numbers')
    clear_store(context, 'bulk_delete_selected', 'bulk_delete_keys')
    await safe_edit_text(q, context, "Массовое удаление отменено.")

async def start_bulk_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    if not files:
        await safe_edit_text(q, context, "Нет ключей."); return
    names = [f[:-5] for f in files]
    url, fallback = create_names_telegraph_page(names, "Отправка ключей", "Список ключей")
    set_store(context, 'bulk_send_keys', names)
    set_flag(context, 'await_bulk_send_numbers', True)
    if url:
        text = ("<b>Отправить ключи</b>\n"
                "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
                f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    else:
        text = ("<b>Отправить ключи</b>\nTelegraph недоступен — список ниже.\n\n<pre>" + escape(fallback) + "</pre>")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))

async def process_bulk_send_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_bulk_send_numbers'): return
    names: List[str] = get_store(context, 'bulk_send_keys', [])
    if not names:
        await update.message.reply_text("Список потерян. Начните заново.")
        clear_flag(context, 'await_bulk_send_numbers'); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs or not idxs:
        msg = "Ошибки:\n" + "\n".join(errs) if errs else "Ничего не выбрано."
        await update.message.reply_text(msg,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))
        return
    selected = [names[i - 1] for i in idxs]
    set_store(context, 'bulk_send_selected', selected)
    clear_flag(context, 'await_bulk_send_numbers')
    preview = "\n".join(selected[:25]) + (f"\n... ещё {len(selected)-25}" if len(selected) > 25 else "")
    await update.message.reply_text(
        f"<b>Отправить ({len(selected)}) ключей:</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_send_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
        ])
    )

async def bulk_send_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import asyncio
    q = update.callback_query; await q.answer()
    selected: List[str] = get_store(context, 'bulk_send_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Список пуст."); return
    await safe_edit_text(q, context, f"Отправляю {len(selected)} ключ(ов)...")
    sent = 0
    for name in selected:
        path = os.path.join(KEYS_DIR, f"{name}.ovpn")
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename=f"{name}.ovpn")
                sent += 1
                await asyncio.sleep(0.25)
            except Exception as e:
                print(f"[{_tz_now_str()}] [bulk_send] error {name}: {e}")
    clear_store(context, 'bulk_send_selected', 'bulk_send_keys')
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"✅ Отправлено: {sent} / {len(selected)}")

async def bulk_send_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    clear_flag(context, 'await_bulk_send_numbers')
    clear_store(context, 'bulk_send_selected', 'bulk_send_keys')
    await safe_edit_text(q, context, "Массовая отправка отменена.")

async def start_bulk_enable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    disabled = [f[:-5] for f in files if is_client_ccd_disabled(f[:-5])]
    if not disabled:
        await safe_edit_text(q, context, "Нет заблокированных клиентов."); return
    url, fallback = create_names_telegraph_page(disabled, "Включение клиентов", "Заблокированные клиенты")
    set_store(context, 'bulk_enable_keys', disabled)
    set_flag(context, 'await_bulk_enable_numbers', True)
    if url:
        text = ("<b>Включить клиентов</b>\n"
                "Формат: all | 1 | 1,2 | 3-7 ...\n"
                f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    else:
        text = ("<b>Включить клиентов</b>\nTelegraph недоступен — список ниже.\n\n<pre>" + escape(fallback) + "</pre>")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))

async def process_bulk_enable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_bulk_enable_numbers'): return
    names: List[str] = get_store(context, 'bulk_enable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        clear_flag(context, 'await_bulk_enable_numbers'); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs or not idxs:
        msg = "Ошибки:\n" + "\n".join(errs) if errs else "Ничего не выбрано."
        await update.message.reply_text(msg,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    set_store(context, 'bulk_enable_selected', selected)
    clear_flag(context, 'await_bulk_enable_numbers')
    preview = "\n".join(selected[:30]) + (f"\n... ещё {len(selected)-30}" if len(selected) > 30 else "")
    await update.message.reply_text(
        f"<b>Включить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_enable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
        ])
    )

async def bulk_enable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = get_store(context, 'bulk_enable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        unblock_client_ccd(name)
    clear_store(context, 'bulk_enable_selected', 'bulk_enable_keys')
    await safe_edit_text(q, context, f"✅ Включено клиентов: {len(selected)}")

async def bulk_enable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    clear_flag(context, 'await_bulk_enable_numbers')
    clear_store(context, 'bulk_enable_selected', 'bulk_enable_keys')
    await safe_edit_text(q, context, "Массовое включение отменено.")

async def start_bulk_disable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    active = [f[:-5] for f in files if not is_client_ccd_disabled(f[:-5])]
    if not active:
        await safe_edit_text(q, context, "Нет активных клиентов."); return
    url, fallback = create_names_telegraph_page(active, "Отключение клиентов", "Активные клиенты")
    set_store(context, 'bulk_disable_keys', active)
    set_flag(context, 'await_bulk_disable_numbers', True)
    if url:
        text = ("<b>Отключить клиентов</b>\n"
                "Формат: all | 1 | 1,2,7 | 3-10 ...\n"
                f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    else:
        text = ("<b>Отключить клиентов</b>\nTelegraph недоступен — список ниже.\n\n<pre>" + escape(fallback) + "</pre>")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))

async def process_bulk_disable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_bulk_disable_numbers'): return
    names: List[str] = get_store(context, 'bulk_disable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        clear_flag(context, 'await_bulk_disable_numbers'); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs or not idxs:
        msg = "Ошибки:\n" + "\n".join(errs) if errs else "Ничего не выбрано."
        await update.message.reply_text(msg,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    set_store(context, 'bulk_disable_selected', selected)
    clear_flag(context, 'await_bulk_disable_numbers')
    preview = "\n".join(selected[:30]) + (f"\n... ещё {len(selected)-30}" if len(selected) > 30 else "")
    await update.message.reply_text(
        f"<b>Отключить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_disable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
        ])
    )

async def bulk_disable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = get_store(context, 'bulk_disable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        block_client_ccd(name); disconnect_client_sessions(name)
    clear_store(context, 'bulk_disable_selected', 'bulk_disable_keys')
    await safe_edit_text(q, context, f"⚠️ Отключено клиентов: {len(selected)}")

async def bulk_disable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    clear_flag(context, 'await_bulk_disable_numbers')
    clear_store(context, 'bulk_disable_selected', 'bulk_disable_keys')
    await safe_edit_text(q, context, "Массовое отключение отменено.")

# ------------------ UPDATE REMOTE ------------------
CLIENT_TEMPLATE_CANDIDATES = ["/etc/openvpn/client-template.txt", "/root/openvpn/client-template.txt"]
def find_client_template_path() -> Optional[str]:
    for p in CLIENT_TEMPLATE_CANDIDATES:
        if os.path.exists(p): return p
    return None

def replace_remote_line_in_text(text: str, new_host: str, new_port: str) -> str:
    lines = []; replaced = False
    for line in text.splitlines():
        if line.strip().startswith("remote "):
            lines.append(f"remote {new_host} {new_port}"); replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"remote {new_host} {new_port}")
    return "\n".join(lines) + "\n"

def update_template_and_ovpn(new_host: str, new_port: str) -> Dict[str, int]:
    stats = {"template_updated": 0, "ovpn_updated": 0, "errors": 0}
    tpl = find_client_template_path()
    if tpl:
        try:
            with open(tpl, "r") as f: old = f.read()
            new = replace_remote_line_in_text(old, new_host, new_port)
            if new != old:
                backup = tpl + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(tpl, backup)
                with open(tpl, "w") as f: f.write(new)
                stats["template_updated"] = 1
        except Exception as e:
            print(f"[{_tz_now_str()}] [update_remote] template error: {e}"); stats["errors"] += 1
    else:
        print(f"[{_tz_now_str()}] [update_remote] template not found")
    for f in get_ovpn_files():
        path = os.path.join(KEYS_DIR, f)
        try:
            with open(path, "r") as fr: oldc = fr.read()
            newc = replace_remote_line_in_text(oldc, new_host, new_port)
            if newc != oldc:
                bak = path + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(path, bak)
                with open(path, "w") as fw: fw.write(newc)
                stats["ovpn_updated"] += 1
        except Exception as e:
            print(f"[{_tz_now_str()}] [update_remote] file {f} error: {e}"); stats["errors"] += 1
    return stats

async def start_update_remote_dialog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    tpl = find_client_template_path()
    tpl_info = tpl if tpl else "не найден"
    text = ("Введите новый remote в формате host:port\n"
            f"(Обнаруженный шаблон: {tpl_info})\nПример: vpn.example.com:1194")
    await safe_edit_text(q, context, text,
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_update_remote")]]))
    set_flag(context, 'await_remote_input', True)

async def process_remote_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_flag(context, 'await_remote_input'): return
    raw = update.message.text.strip()
    if ':' not in raw:
        await update.message.reply_text("Формат неверный. Нужно host:port. Пример: myvpn.com:1194"); return
    host, port = raw.split(':', 1)
    host, port = host.strip(), port.strip()
    if not host or not port.isdigit():
        await update.message.reply_text("Некорректные host или port."); return
    stats = update_template_and_ovpn(host, port)
    clear_flag(context, 'await_remote_input')
    await update.message.reply_text(
        f"✅ Обновление завершено.\nШаблон: {stats['template_updated']}\n.ovpn изменено: {stats['ovpn_updated']}\nОшибок: {stats['errors']}"
    )

# ------------------ HELP TEXT ------------------
HELP_TEXT = """❓ Справка

• Список / Статистика ключей
• Создание/Удаление/Отправка/Блокировка/Включение
• Логические сроки (продлевай через «⌛ Обновить ключ»)
• Трафик и очистка
• Бэкап/восстановление
• Обновление remote
• Мониторинг подключений/блокировки

На этом сервере используется TLS-Crypt v2: .ovpn включает <tls-crypt-v2> блок автоматически.
"""

# ------------------ BUTTON HANDLER ------------------
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Доступ запрещён.", show_alert=True); return
    await q.answer()
    data = q.data
    try:
        if data == 'refresh':
            await safe_edit_text(q, context, format_clients_by_certs(), parse_mode="HTML")

        elif data == 'stats':
            clients, online_names, tunnel_ips = parse_openvpn_status()
            files = get_ovpn_files()
            files = sorted(files, key=lambda x: _natural_key(x[:-5]))
            lines = ["<b>Статус всех ключей:</b>"]
            for f in files:
                name = f[:-5]
                st = "⛔" if is_client_ccd_disabled(name) else ("🟢" if name in online_names else "🔴")
                lines.append(f"{st} {name}")
            text = "\n".join(lines)
            msgs = split_message(text)
            await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
            for m in msgs[1:]:
                await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

        elif data == 'traffic':
            save_traffic_db(force=True)
            await safe_edit_text(q, context, build_traffic_report(), parse_mode="HTML")

        elif data == 'traffic_clear':
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Да", callback_data="confirm_clear_traffic")],
                [InlineKeyboardButton("❌ Нет", callback_data="cancel_clear_traffic")]
            ])
            await safe_edit_text(q, context, "Очистить накопленный трафик?", reply_markup=kb)
        elif data == 'confirm_clear_traffic':
            clear_traffic_stats(); await safe_edit_text(q, context, "Очищено.")
        elif data == 'cancel_clear_traffic':
            await safe_edit_text(q, context, "Отменено.")

        elif data == 'update_remote':
            await start_update_remote_dialog(update, context)
        elif data == 'cancel_update_remote':
            clear_flag(context, 'await_remote_input')
            await safe_edit_text(q, context, "Отменено.")

        elif data == 'renew_key':
            await renew_key_request(update, context)
        elif data.startswith('renew_'):
            await renew_key_select_handler(update, context)
        elif data == 'cancel_renew':
            await renew_cancel(update, context)

        elif data == 'backup_menu':
            await backup_menu(update, context)
        elif data == 'restore_menu':
            await restore_menu(update, context)
        elif data == 'backup_create':
            await perform_backup_and_send(update, context)
        elif data == 'backup_list':
            await show_backup_list(update, context)
        elif data.startswith('backup_info_'):
            await show_backup_info(update, context, data.replace('backup_info_', '', 1))
        elif data.startswith('backup_send_'):
            await send_backup_file(update, context, data.replace('backup_send_', '', 1))
        elif data.startswith('restore_dry_'):
            await restore_dry_run(update, context, data.replace('restore_dry_', '', 1))
        elif data.startswith('restore_apply_'):
            await restore_apply(update, context, data.replace('restore_apply_', '', 1))
        elif data.startswith('backup_delete_confirm_'):
            await backup_delete_apply(update, context, data.replace('backup_delete_confirm_', '', 1))
        elif data.startswith('backup_delete_'):
            await backup_delete_prompt(update, context, data.replace('backup_delete_', '', 1))

        elif data == 'bulk_delete_start':
            await start_bulk_delete(update, context)
        elif data == 'bulk_delete_confirm':
            await bulk_delete_confirm(update, context)
        elif data == 'cancel_bulk_delete':
            await bulk_delete_cancel(update, context)

        elif data == 'bulk_send_start':
            await start_bulk_send(update, context)
        elif data == 'bulk_send_confirm':
            await bulk_send_confirm(update, context)
        elif data == 'cancel_bulk_send':
            await bulk_send_cancel(update, context)

        elif data == 'bulk_enable_start':
            await start_bulk_enable(update, context)
        elif data == 'bulk_enable_confirm':
            await bulk_enable_confirm(update, context)
        elif data == 'cancel_bulk_enable':
            await bulk_enable_cancel(update, context)

        elif data == 'bulk_disable_start':
            await start_bulk_disable(update, context)
        elif data == 'bulk_disable_confirm':
            await bulk_disable_confirm(update, context)
        elif data == 'cancel_bulk_disable':
            await bulk_disable_cancel(update, context)

        elif data == 'update_info':
            await send_simple_update_command(update, context)
        elif data == 'copy_update_cmd':
            await resend_update_command(update, context)

        elif data == 'keys_expiry':
            await view_keys_expiry_handler(update, context)

        elif data == 'send_ipp':
            ipp_path = "/etc/openvpn/ipp.txt"
            if os.path.exists(ipp_path):
                with open(ipp_path, "rb") as f:
                    await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename="ipp.txt")
                await safe_edit_text(q, context, "ipp.txt отправлен.")
            else:
                await safe_edit_text(q, context, "ipp.txt не найден.")

        elif data == 'block_alert':
            await safe_edit_text(q, context,
                                 "🔔 Мониторинг блокировки включен.\n"
                                 f"Порог MIN_ONLINE_ALERT = {MIN_ONLINE_ALERT}\n"
                                 "Оповещения если:\n • Все клиенты оффлайн\n • Онлайн меньше порога\n"
                                 "Проверка каждые 10с. Истечения — каждые 12ч.")

        elif data == 'help':
            await send_help_messages(context, q.message.chat_id)

        elif data == 'log':
            await log_request(update, context)

        elif data == 'create_key':
            await safe_edit_text(q, context, "Введите имя нового клиента:")
            set_flag(context, 'await_key_name', True)

        elif data == 'home':
            await context.bot.send_message(q.message.chat_id, "Главное меню уже показано. Для обновления нажми /start.")
        else:
            await safe_edit_text(q, context, "Неизвестная команда.")
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[{_tz_now_str()}] [button_handler] error for '{data}': {e}\n{tb}")
        try:
            await context.bot.send_message(chat_id=q.message.chat_id, text=f"Ошибка обработчика: {e}")
        except:
            pass

# ------------------ HELP SENDER ------------------
def build_help_messages():
    esc = escape(HELP_TEXT.strip("\n"))
    lines = esc.splitlines()
    parts, block, cur_len = [], [], 0
    LIMIT = 3500
    for line in lines:
        l = len(line) + 1
        if block and cur_len + l > LIMIT:
            content = "\n".join(block)
            parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")
            block = [line]; cur_len = l
        else:
            block.append(line); cur_len += l
    if block:
        content = "\n".join(block)
        parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")
    return parts

async def send_help_messages(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    for part in build_help_messages():
        await context.bot.send_message(chat_id=chat_id, text=part, parse_mode="HTML")

# ------------------ MAIN ------------------
def main():
    app = Application.builder().token(TOKEN).build()
    load_traffic_db()
    load_client_meta()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))
    app.add_handler(CommandHandler("backup_now", cmd_backup_now))
    app.add_handler(CommandHandler("backup_list", cmd_backup_list))
    app.add_handler(CommandHandler("backup_restore", cmd_backup_restore))
    app.add_handler(CommandHandler("backup_restore_apply", cmd_backup_restore_apply))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))
    app.add_handler(CallbackQueryHandler(button_handler))
    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))
    app.run_polling()

if __name__ == '__main__':
    main()