#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if [[ $EUID -ne 0 ]]; then
  echo "Запустите как root" >&2
  exit 1
fi

echo "[*] Устанавливаю базовые утилиты (curl, git)..."
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl git

REPO_URL="https://github.com/XSFORM/OpenVpnTLS2.git"
INSTALL_DIR="/root/OpenVpnTLS2"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  echo "[*] Репозиторий уже есть, обновляю..."
  git -C "$INSTALL_DIR" pull --ff-only
else
  echo "[*] Клонирую репозиторий в $INSTALL_DIR ..."
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

echo "[*] Выдаю права на скрипты..."
chmod +x install.sh openvpn-install.sh || true

echo "[*] Запускаю установку..."
./install.sh

echo "[*] Делаю удобные ярлыки для OpenVPN инсталлятора..."
cp -f openvpn-install.sh /root/openvpn-install.sh
chmod +x /root/openvpn-install.sh
ln -sf /root/openvpn-install.sh /usr/local/bin/openvpn-install

echo
echo "Готово!"
echo "- Бот запущен как vpn_bot.service (journalctl -u vpn_bot.service -f)"
echo "- OpenVPN мастер: /root/openvpn-install.sh (или команда: openvpn-install)"