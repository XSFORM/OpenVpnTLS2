#!/bin/bash
set -e

# 1. Установим OpenVPN через ваш скрипт
bash ./openvpn-install.sh

# 2. Спросим у пользователя токен и ID Telegram
echo "Введите Telegram BOT TOKEN (например, 123456:ABC...):"
read -r BOT_TOKEN
echo "Введите ваш Telegram ID (например, 123456789):"
read -r ADMIN_ID

# 3. Копируем бота в /root/monitor_bot
mkdir -p /root/monitor_bot
cp -r monitor_bot/* /root/monitor_bot/

# 4. Пишем config.py с токеном и id
cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF

# 5. Устанавливаем Python и зависимости
apt update
apt install -y python3 python3-pip
pip3 install -r /root/monitor_bot/requirements.txt

# 6. Копируем systemd unit
cp vpn_bot.service /etc/systemd/system/vpn_bot.service

# 7. Перезагружаем systemd и включаем сервис
systemctl daemon-reload
systemctl enable --now vpn_bot.service

echo "Установка завершена! Ваш VPN-бот запущен."
