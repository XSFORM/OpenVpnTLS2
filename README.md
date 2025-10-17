# OpenVpnTLS2

## Установка (одной командой)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/XSFORM/OpenVpnTLS2/main/bootstrap.sh)
```

Скрипт:
- установит curl/git (если нет),
- клонирует/обновит репозиторий в `/root/OpenVpnTLS2`,
- запустит `install.sh` (доустановит зависимости, настроит сервис бота),
- создаст ярлык `/root/openvpn-install.sh` и команду `openvpn-install`.

По ходу установки вас попросят:
- ввести Telegram BOT TOKEN,
- ввести ваш Telegram ID.

Логи бота:
```bash
journalctl -u vpn_bot.service -f
```

## Управление OpenVPN

- Мастер-скрипт: `/root/openvpn-install.sh`
- Или из любой директории: `openvpn-install`

> Если у вас есть свой инсталлятор OpenVPN (`install_openvpn_xormask.sh`) — положите его рядом и запустите установку. Если файла нет, будут установлены `openvpn` и `easy-rsa` из репозиториев, создан базовый `client-template.txt` (серверный `server.conf` автоматически не генерируется).