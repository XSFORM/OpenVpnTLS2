#!/bin/bash
set -e

# 1. Копируем openvpn-install.sh в /root (если нужно обновить — перезаписываем)
cp openvpn-install.sh /root/openvpn-install.sh
chmod +x /root/openvpn-install.sh

# 2. Запускаем его из /root
bash /root/openvpn-install.sh

# 3. Дальше как раньше...
echo "Введите Telegram BOT TOKEN (например, 123456:ABC...):"
read -r BOT_TOKEN
echo "Введите ваш Telegram ID (например, 123456789):"
read -r ADMIN_ID

mkdir -p /root/monitor_bot
cp -r monitor_bot/* /root/monitor_bot/

cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF

apt update
apt install git
apt install -y python3 python3-pip
pip3 install -r /root/monitor_bot/requirements.txt
pip3 install pyopenssl

cp vpn_bot.service /etc/systemd/system/vpn_bot.service

systemctl daemon-reload
systemctl enable --now vpn_bot.service

echo "Установка завершена! Ваш VPN-бот запущен. Для управления OpenVPN используйте /root/openvpn-install.sh"