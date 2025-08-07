from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
)
import subprocess
import os
import glob

CHOOSE_CONF, CLIENT_NAME, EXPIRE_DAYS = range(3)

def get_server_confs():
    # Получаем список конфигов server-PORTPROTO.conf
    return sorted(glob.glob("/etc/openvpn/server-*.conf"))

async def create_key_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != context.bot_data['ADMIN_ID']:
        await update.message.reply_text("Доступ запрещён.")
        return ConversationHandler.END
    confs = get_server_confs()
    if not confs:
        await update.message.reply_text("Нет доступных OpenVPN конфигураций!")
        return ConversationHandler.END
    keyboard = []
    for i, conf in enumerate(confs, 1):
        keyboard.append([InlineKeyboardButton(
            f"{i}. {os.path.basename(conf)}", callback_data=f"conf_{i}")])
    await update.message.reply_text(
        "Выберите конфигурацию OpenVPN, для которой создать ключ:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    context.user_data['server_confs'] = confs
    return CHOOSE_CONF

async def choose_conf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    idx = int(query.data.split('_')[1]) - 1
    confs = context.user_data['server_confs']
    if idx < 0 or idx >= len(confs):
        await query.edit_message_text("Некорректный выбор.")
        return ConversationHandler.END
    context.user_data['chosen_conf'] = confs[idx]
    await query.edit_message_text("Введите имя ключа (только латиница и цифры, без пробелов):")
    return CLIENT_NAME

async def client_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    name = update.message.text.strip()
    if not name.isalnum():
        await update.message.reply_text("❌ Некорректное имя. Только латиница и цифры, без пробелов:")
        return CLIENT_NAME
    context.user_data['client_name'] = name
    await update.message.reply_text("Введите срок действия ключа в днях (по умолчанию 30):")
    return EXPIRE_DAYS

async def expire_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    days = update.message.text.strip()
    if not days.isdigit():
        days = "30"
    context.user_data['expire_days'] = days
    name = context.user_data['client_name']
    conf = context.user_data['chosen_conf']
    days = context.user_data['expire_days']

    # Готовим команду для создания ключа через easyrsa
    EASYRSA_DIR = "/etc/openvpn/easy-rsa"
    try:
        # Создаем ключ и сертификат:
        subprocess.run(
            f'cd {EASYRSA_DIR} && ./easyrsa build-client-full {name} nopass',
            shell=True, check=True)
        # Генерируем .ovpn для выбранной конфигурации
        # Получаем CA, cert, key, tls-auth, и шаблон .ovpn
        ca = open(f"{EASYRSA_DIR}/pki/ca.crt").read()
        crt = open(f"{EASYRSA_DIR}/pki/issued/{name}.crt").read()
        key = open(f"{EASYRSA_DIR}/pki/private/{name}.key").read()
        tls = ""
        if os.path.exists(f"{EASYRSA_DIR}/ta.key"):
            tls = open(f"{EASYRSA_DIR}/ta.key").read()
        # Определяем порт/протокол сервера
        with open(conf) as f:
            conf_lines = f.read().splitlines()
        port = next((l.split()[1] for l in conf_lines if l.startswith("port ")), "1194")
        proto = next((l.split()[1] for l in conf_lines if l.startswith("proto ")), "udp")
        remote = "vpn.yourdomain.tld"  # Или ваш IP, или спрашивать у пользователя

        # Генерируем ovpn файл
        ovpn = f"""
client
dev tun
proto {proto}
remote {remote} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-128-GCM
auth SHA256
setenv opt block-outside-dns
verb 3
<ca>
{ca}</ca>
<cert>
{crt}</cert>
<key>
{key}</key>
"""
        if tls:
            ovpn += f"<tls-auth>\n{tls}\n</tls-auth>\nkey-direction 1\n"

        # Сохраняем ovpn
        ovpn_path = f"/root/{name}.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn)
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка создания ключа: {e}")
        return ConversationHandler.END

    await update.message.reply_text(
        f"✅ Ключ <b>{name}</b> создан для {os.path.basename(conf)}!\nСрок действия: {days} дней.\nФайл: {ovpn_path}",
        parse_mode="HTML"
    )
    return ConversationHandler.END

create_key_conv = ConversationHandler(
    entry_points=[CallbackQueryHandler(create_key_start, pattern="^create_key$")],
    states={
        CHOOSE_CONF: [CallbackQueryHandler(choose_conf, pattern="^conf_")],
        CLIENT_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, client_name)],
        EXPIRE_DAYS: [MessageHandler(filters.TEXT & ~filters.COMMAND, expire_days)],
    },
    fallbacks=[],
)