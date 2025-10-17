#!/bin/bash
set -euo pipefail

echo "[*] Начало установки VPN бота (server-ready)."

if [[ $EUID -ne 0 ]]; then
  echo "Запусти от root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
BASE_DIR="$(pwd)"

apt_install() {
  local pkgs=()
  for p in "$@"; do
    if ! dpkg -s "$p" &>/dev/null; then
      pkgs+=("$p")
    fi
  done
  if ((${#pkgs[@]})); then
    echo "[*] apt install: ${pkgs[*]}"
    apt-get install -y --no-install-recommends "${pkgs[@]}"
  else
    echo "[*] Пакеты уже установлены: $*"
  fi
}

ensure_dir() { mkdir -p "$1"; }

echo "[*] apt update ..."
apt-get update -y

echo "[*] Устанавливаю системные зависимости ..."
apt_install ca-certificates curl git unzip jq qrencode openssl
apt_install python3 python3-pip python3-venv
apt_install build-essential python3-dev libffi-dev libssl-dev pkg-config

# --- OpenVPN/Easy-RSA (если рядом нет кастомного установщика) ---
if [[ -f "$BASE_DIR/install_openvpn_xormask.sh" ]]; then
  echo "[*] Запуск install_openvpn_xormask.sh ..."
  cp "$BASE_DIR/install_openvpn_xormask.sh" /root/install_openvpn_xormask.sh
  chmod +x /root/install_openvpn_xormask.sh
  bash /root/install_openvpn_xormask.sh
else
  echo "[!] install_openvpn_xormask.sh не найден — ставлю openvpn/easy-rsa из репозиториев."
  apt_install openvpn easy-rsa iptables-persistent || true
  ensure_dir /etc/openvpn /etc/openvpn/client /etc/openvpn/ccd /etc/openvpn/keys-v2
  if [[ ! -f /etc/openvpn/client-template.txt ]]; then
    cat >/etc/openvpn/client-template.txt <<'TPL'
# Client template (remote будет подставляться ботом)
client
dev tun
proto udp
nobind
persist-key
persist-tun
resolv-retry infinite
remote-cert-tls server
auth SHA256
cipher AES-128-GCM
ncp-ciphers AES-128-GCM
tls-version-min 1.2
verb 3
# Для tls-crypt v2 ключ бот может вклеить inline
# key-direction 1  # (для tls-crypt v1, если нужно)
# remote vpn.example.com 1194  # подставляется ботом
TPL
    echo "[*] Создан /etc/openvpn/client-template.txt"
  fi
fi

# --- Данные бота ---
read -rp "Введите Telegram BOT TOKEN: " BOT_TOKEN
read -rp "Введите ваш Telegram ID: " ADMIN_ID

echo "[*] Готовлю /root/monitor_bot ..."
ensure_dir /root/monitor_bot

if [[ -d "$BASE_DIR/monitor_bot" ]]; then
  cp -r "$BASE_DIR/monitor_bot/"* /root/monitor_bot/
else
  echo "[!] Директория monitor_bot не найдена рядом со скриптом. Поместите её и запустите снова."
  exit 1
fi

cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF
echo "[*] Создан /root/monitor_bot/config.py"

echo "[*] Обновляю pip/setuptools/wheel ..."
python3 -m pip install --upgrade pip setuptools wheel

REQ_FILE="/root/monitor_bot/requirements.txt"
if [[ ! -f "$REQ_FILE" ]]; then
  echo "[*] requirements.txt не найден — создаю дефолтный."
  cat > "$REQ_FILE" <<'REQ'
python-telegram-bot==20.3
requests
pytz
pyOpenSSL
cryptography
REQ
fi

echo "[*] Устанавливаю зависимости из requirements.txt ..."
python3 -m pip install -r "$REQ_FILE"

echo "[*] Проверка импортов ..."
python3 - <<'PY'
mods = ["requests","telegram","OpenSSL","pytz","cryptography"]
import importlib, sys
missing=[]
for m in mods:
    try:
        importlib.import_module(m)
        print(f"[OK] {m}")
    except Exception as e:
        print(f"[FAIL] {m} -> {e}")
        missing.append(m)
if missing:
    print("===> Отсутствуют модули:", ", ".join(missing))
    sys.exit(1)
PY

# --- systemd unit для бота ---
if [[ -f "$BASE_DIR/vpn_bot.service" ]]; then
  cp "$BASE_DIR/vpn_bot.service" /etc/systemd/system/vpn_bot.service
  echo "[*] Сервисный файл скопирован."
elif [[ ! -f /etc/systemd/system/vpn_bot.service ]]; then
  echo "[!] vpn_bot.service не найден — создаю типовой."
  cat > /etc/systemd/system/vpn_bot.service <<'UNIT'
[Unit]
Description=VPN Telegram Monitor Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/monitor_bot
ExecStart=/usr/bin/python3 /root/monitor_bot/openvpn_monitor_bot.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT
fi

echo "[*] Перезапуск systemd (бот) ..."
systemctl daemon-reload
systemctl enable --now vpn_bot.service || {
  echo "[!] Не удалось запустить сервис бота. Смотри: journalctl -u vpn_bot.service -n 80"
  exit 1
}

echo
echo "========================================================"
echo "Установка завершена!"
echo "Бот: /root/monitor_bot/openvpn_monitor_bot.py"
echo "Конфиг бота: /root/monitor_bot/config.py"
echo "Логи бота: journalctl -u vpn_bot.service -f"
echo
echo "OpenVPN:"
echo "- Пакеты openvpn/easy-rsa установлены (если не использовался ваш инсталлятор)."
echo "- Шаблон клиента: /etc/openvpn/client-template.txt"
echo "- server.conf не создавался автоматически (используйте свой готовый)."
echo "========================================================"