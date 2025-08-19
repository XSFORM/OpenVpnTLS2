#!/bin/bash

echo "[*] Устанавливаем обычный OpenVPN ..."
wget -q https://git.io/v1jlQ -O openvpn-install.sh && bash openvpn-install.sh

echo "[*] Удаляем обычный OpenVPN ..."
apt remove openvpn -y

echo "[*] Устанавливаем OpenVPN с поддержкой XOR ..."
wget -q https://raw.githubusercontent.com/x0r2d2/openvpn-xor/main/openvpn_xor_install.sh -O openvpn_xor_install.sh
chmod +x openvpn_xor_install.sh
bash openvpn_xor_install.sh

echo "[*] Перемещаем openvpn-install.sh в /root/ ..."
mv openvpn-install.sh /root/

# Подождём немного, чтобы файлы конфигурации появились
sleep 2

SERVER_CONF="/etc/openvpn/server.conf"
CLIENT_TEMPLATE="/etc/openvpn/client-template.txt"

echo "[*] Добавляем scramble xormask 5 и push-маршруты в конфиги ..."

if [ -f "$SERVER_CONF" ]; then
    grep -q "scramble xormask" "$SERVER_CONF" || echo "scramble xormask 5" >> "$SERVER_CONF"

    # Добавляем push-маршруты
    for route in \
        "192.168.0.0 255.255.0.0" \
        "10.0.0.0 255.0.0.0" \
        "172.16.0.0 255.240.0.0" \
        "27.34.176.0 255.255.255.0" \
        "57.90.150.0 255.255.254.0" \
        "77.83.59.0 255.255.255.0" \
        "82.198.24.0 255.255.255.0" \
        "91.202.233.0 255.255.255.0" \
        "93.171.174.0 255.255.255.0" \
        "93.171.220.0 255.255.252.0" \
        "94.102.176.0 255.255.240.0" \
        "95.85.96.0 255.255.224.0" \
        "103.220.0.0 255.255.252.0" \
        "119.235.112.0 255.255.240.0" \
        "154.30.29.0 255.255.255.0" \
        "177.93.143.0 255.255.255.0" \
        "178.171.66.0 255.255.254.0" \
        "185.69.184.0 255.255.252.0" \
        "185.246.72.0 255.255.252.0" \
        "196.48.195.0 255.255.255.0" \
        "196.56.195.0 255.255.255.0" \
        "196.57.195.0 255.255.255.0" \
        "196.58.195.0 255.255.255.0" \
        "196.197.195.0 255.255.255.0" \
        "196.198.195.0 255.255.255.0" \
        "196.199.195.0 255.255.255.0" \
        "216.250.8.0 255.255.248.0" \
        "217.8.117.0 255.255.255.0" \
        "217.174.224.0 255.255.240.0"
    do
        ip=$(echo $route | cut -d' ' -f1)
        mask=$(echo $route | cut -d' ' -f2)
        line="push \"route $ip $mask net_gateway\""
        grep -q "$line" "$SERVER_CONF" || echo "$line" >> "$SERVER_CONF"
    done
else
    echo "⚠️ $SERVER_CONF не найден"
fi

if [ -f "$CLIENT_TEMPLATE" ]; then
    grep -q "scramble xormask" "$CLIENT_TEMPLATE" || echo "scramble xormask 5" >> "$CLIENT_TEMPLATE"
else
    echo "⚠️ $CLIENT_TEMPLATE не найден"
fi

echo "[✓] Установка OpenVPN XOR завершена!"
