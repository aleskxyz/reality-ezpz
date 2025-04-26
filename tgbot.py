import io
import os
import re
import subprocess

import qrcode
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

token = os.environ["BOT_TOKEN"]
admin = os.environ["BOT_ADMIN"]
username_regex = re.compile("^[a-zA-Z0-9]+$")
command = "bash <(curl -sL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh) "


def get_users_ezpz():
    local_command = command + "--list-users"
    return run_command(local_command).split("\n")[:-1]


def get_config_ezpz(username):
    local_command = command + f"--show-user {username} | grep -E '://|^\\{{\"dns\"'"
    return run_command(local_command).split("\n")[:-1]


def delete_user_ezpz(username):
    local_command = command + f"--delete-user {username}"
    run_command(local_command)
    return


def add_user_ezpz(username):
    local_command = command + f"--add-user {username}"
    run_command(local_command)
    return


def run_command(command):
    process = subprocess.Popen(
        ["/bin/bash", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output, _ = process.communicate()
    return output.decode()


def restricted(func):
    async def wrapped(
        update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs
    ):
        username = None
        if update.message:
            username = update.message.chat.username
        elif update.callback_query and update.callback_query.message:
            username = update.callback_query.message.chat.username
        admin_list = admin.split(",")
        if username in admin_list:
            return await func(update, context, *args, **kwargs)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="You are not authorized to use this bot.",
            )

    return wrapped


@restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    commands_text = "Reality-EZPZ User Management Bot\n\nChoose an option:"
    keyboard = [
        [InlineKeyboardButton("Show User", callback_data="show_user")],
        [InlineKeyboardButton("Add User", callback_data="add_user")],
        [InlineKeyboardButton("Delete User", callback_data="delete_user")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=commands_text, reply_markup=reply_markup
    )


@restricted
async def users_list(
    update: Update, context: ContextTypes.DEFAULT_TYPE, text, callback
):
    keyboard = []
    for user in get_users_ezpz():
        keyboard.append(
            [InlineKeyboardButton(user, callback_data=f"{callback}!{user}")]
        )
    keyboard.append([InlineKeyboardButton("Back", callback_data="start")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
    )


@restricted
async def show_user(update: Update, context: ContextTypes.DEFAULT_TYPE, username):
    keyboard = [[InlineKeyboardButton("Back", callback_data="show_user")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f'Config for "{username}":',
        parse_mode="HTML",
    )
    config_list = get_config_ezpz(username)
    ipv6_pattern = r'"server":"[0-9a-fA-F:]+"'

    for config in config_list:
        if config.endswith("-ipv6") or re.search(ipv6_pattern, config):
            config_text = f"IPv6 Config:\n<pre>{config}</pre>"
        else:
            config_text = f"<pre>{config}</pre>"

        qr_img = qrcode.make(config)
        bio = io.BytesIO()
        qr_img.save(bio, "PNG")
        bio.seek(0)

        await context.bot.send_photo(
            chat_id=update.effective_chat.id,
            photo=bio,
            caption=config_text,
            parse_mode="HTML",
            reply_markup=reply_markup,
        )


@restricted
async def delete_user(update: Update, context: ContextTypes.DEFAULT_TYPE, username):
    keyboard = []
    if len(get_users_ezpz()) == 1:
        text = "You cannot delete the only user.\nAt least one user is needed.\nCreate a new user, then delete this one."
        keyboard.append([InlineKeyboardButton("Back", callback_data="start")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(
            chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
        )
        return
    text = f'Are you sure to delete "{username}"?'
    keyboard.append(
        [InlineKeyboardButton("Delete", callback_data=f"approve_delete!{username}")]
    )
    keyboard.append([InlineKeyboardButton("Cancel", callback_data="delete_user")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
    )


@restricted
async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = "Enter the username:"
    keyboard = []
    keyboard.append([InlineKeyboardButton("Cancel", callback_data="cancel")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    context.user_data["expected_input"] = "username"
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
    )


@restricted
async def approve_delete(update: Update, context: ContextTypes.DEFAULT_TYPE, username):
    delete_user_ezpz(username)
    text = f"User {username} has been deleted."
    keyboard = []
    keyboard.append([InlineKeyboardButton("Back", callback_data="start")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
    )


@restricted
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "expected_input" in context.user_data:
        del context.user_data["expected_input"]
    await start(update, context)


@restricted
async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    response = query.data.split("!")
    if len(response) == 1:
        if response[0] == "start":
            await start(update, context)
        elif response[0] == "cancel":
            await cancel(update, context)
        elif response[0] == "show_user":
            await users_list(
                update, context, "Select user to view config:", "show_user"
            )
        elif response[0] == "delete_user":
            await users_list(update, context, "Select user to delete:", "delete_user")
        elif response[0] == "add_user":
            await add_user(update, context)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="Button pressed: {}".format(response[0]),
            )
    if len(response) > 1:
        if response[0] == "show_user":
            await show_user(update, context, response[1])
        if response[0] == "delete_user":
            await delete_user(update, context, response[1])
        if response[0] == "approve_delete":
            await approve_delete(update, context, response[1])


@restricted
async def user_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "expected_input" in context.user_data:
        expected_input = context.user_data["expected_input"]
        del context.user_data["expected_input"]
        if expected_input == "username":
            username = update.message.text
            if username in get_users_ezpz():
                await update.message.reply_text(
                    f'User "{username}" exists, try another username.'
                )
                await add_user(update, context)
                return
            if not username_regex.match(username):
                await update.message.reply_text(
                    "Username can only contains A-Z, a-z and 0-9, try another username."
                )
                await add_user(update, context)
                return
            add_user_ezpz(username)
            await update.message.reply_text(f'User "{username}" is created.')
            await show_user(update, context, username)


def main():
    # Create the Application
    application = Application.builder().token(token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, user_input))

    # Start the Bot - using the non-blocking approach
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
