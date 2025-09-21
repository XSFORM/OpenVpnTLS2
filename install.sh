#!/bin/bash
set -e

echo "[*] Начало установки VPN бота (simple)."

# --- Проверки окружения ---
if [[ $EUID -ne 0 ]]; then
  echo "Запусти от root." >&2
  exit 1
fi

# Определяем каталог, откуда запускаем (чтобы копировать файлы относительно него)
BASE_DIR="$(pwd)"

# --- Шаг 1. Копируем и запускаем установку OpenVPN (если нужен этот шаг) ---
if [[ -f "$BASE_DIR/install_openvpn_xormask.sh" ]]; then
  echo "[*] Копирую install_openvpn_xormask.sh в /root ..."
  cp "$BASE_DIR/install_openvpn_xormask.sh" /root/install_openvpn_xormask.sh
  chmod +x /root/install_openvpn_xormask.sh
  echo "[*] Запуск install_openvpn_xormask.sh ..."
  bash /root/install_openvpn_xormask.sh
else
  echo "[!] Файл install_openvpn_xormask.sh не найден в $BASE_DIR — пропускаю шаг OpenVPN."
fi

# --- Шаг 2. Ввод токена и ID ---
read -rp "Введите Telegram BOT TOKEN: " BOT_TOKEN
read -rp "Введите ваш Telegram ID: " ADMIN_ID

# --- Шаг 3. Каталог бота ---
echo "[*] Готовлю /root/monitor_bot ..."
mkdir -p /root/monitor_bot

# Копируем содержимое директории monitor_bot (если она есть рядом)
if [[ -d "$BASE_DIR/monitor_bot" ]]; then
  cp -r "$BASE_DIR/monitor_bot/"* /root/monitor_bot/
else
  echo "[!] Директория monitor_bot не найдена рядом со скриптом. Пожалуйста, помести её и перезапусти."
  exit 1
fi

# --- Шаг 4. Создаём config.py ---
cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF
echo "[*] Создан /root/monitor_bot/config.py"

# --- Шаг 5. Установка зависимостей ---
echo "[*] apt update ..."
apt update -y

echo "[*] Устанавливаю базовые пакеты ..."
apt install -y python3 python3-pip git

# (На Debian 11 иногда полезно сразу тянуть эти пакеты, но не обязательно — pip их поставит)
apt install -y python3-requests python3-pytz python3-openssl || true

# --- Шаг 6. requirements ---
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

echo "[*] Обновляю pip ..."
python3 -m pip install --upgrade pip

echo "[*] Устанавливаю зависимости из requirements.txt ..."
python3 -m pip install -r "$REQ_FILE"

# Быстрая проверка импортов
echo "[*] Проверка модулей ..."
python3 - <<'PY'
mods = ["requests","telegram","OpenSSL","pytz","cryptography"]
import importlib, sys
missing = []
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

# --- Шаг 7. systemd unit ---
if [[ -f "$BASE_DIR/vpn_bot.service" ]]; then
  cp "$BASE_DIR/vpn_bot.service" /etc/systemd/system/vpn_bot.service
  echo "[*] Сервисный файл скопирован."
elif [[ ! -f /etc/systemd/system/vpn_bot.service ]]; then
  echo "[!] vpn_bot.service не найден. Создаю типовой."
  cat > /etc/systemd/system/vpn_bot.service <<'UNIT'
[Unit]
Description=VPN Telegram Monitor Bot
After=network.target

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

# --- Шаг 8. Запуск ---
echo "[*] Перезапуск systemd ..."
systemctl daemon-reload
systemctl enable --now vpn_bot.service || {
  echo "[!] Не удалось запустить сервис. Смотри: journalctl -u vpn_bot.service -n 50"
  exit 1
}

echo
echo "========================================================"
echo "Установка завершена!"
echo "Файл конфигурации: /root/monitor_bot/config.py"
echo "Логи: journalctl -u vpn_bot.service -f"
echo "При проблемах: python3 /root/monitor_bot/openvpn_monitor_bot.py (ручной запуск)"
echo "========================================================"