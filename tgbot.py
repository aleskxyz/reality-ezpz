import asyncio
import io
import os
import re

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


class ScriptExecutionError(Exception):
    """Custom exception for errors when running the external script."""

    def __init__(self, message, stdout, stderr, returncode):
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    def __str__(self):
        return f"{super().__str__()} (Exit code: {self.returncode})\nStderr: {self.stderr}\nStdout: {self.stdout}"


async def async_run_script_command(cmd: str) -> str:
    """
    Run a shell command asynchronously and return stdout.
    Raises ScriptExecutionError if the command fails.
    """
    # Use asyncio.create_subprocess_exec for async subprocess
    # Need shell=True because the command string uses shell features like <()
    process = await asyncio.create_subprocess_exec(
        "/bin/bash",
        "-c",
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()

    stdout_str = stdout.decode().strip()
    stderr_str = stderr.decode().strip()

    if process.returncode != 0:
        raise ScriptExecutionError(
            f"Script command failed: {cmd}",
            stdout=stdout_str,
            stderr=stderr_str,
            returncode=process.returncode,
        )

    return stdout_str


async def get_users_ezpz():
    local_command = command + "--list-users"
    try:
        output = await async_run_script_command(local_command)
        users = output.split("\n")
        if users and users[-1] == "":
            users.pop()
        return users
    except ScriptExecutionError as e:
        print(f"Error listing users: {e}")
        return []


async def get_config_ezpz(username: str):
    local_command = command + f"--show-user {username} | grep -E '://|^\\{{\"dns\"'"
    try:
        output = await async_run_script_command(local_command)
        configs = output.split("\n")
        if configs and configs[-1] == "":
            configs.pop()
        return configs
    except ScriptExecutionError as e:
        print(f"Error getting config for {username}: {e}")
        return []


async def delete_user_ezpz(username: str):
    local_command = command + f"--delete-user {username}"
    try:
        await async_run_script_command(local_command)
        return True
    except ScriptExecutionError as e:
        print(f"Error deleting user {username}: {e}")
        return False


async def add_user_ezpz(username: str):
    local_command = command + f"--add-user {username}"
    try:
        await async_run_script_command(local_command)
        return True
    except ScriptExecutionError as e:
        print(f"Error adding user {username}: {e}")
        return False


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
        if username and username in admin_list:
            return await func(update, context, *args, **kwargs)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="You are not authorized to use this bot. Your username is not in the admin list.",
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
    update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, callback: str
):
    keyboard = []
    users = await get_users_ezpz()
    if not users:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="Could not retrieve user list or no users found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("Back", callback_data="start")]]
            ),
        )
        return

    for user in users:
        keyboard.append(
            [InlineKeyboardButton(user, callback_data=f"{callback}!{user}")]
        )
    keyboard.append([InlineKeyboardButton("Back", callback_data="start")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup
    )


@restricted
async def show_user(update: Update, context: ContextTypes.DEFAULT_TYPE, username: str):
    keyboard = [[InlineKeyboardButton("Back", callback_data="show_user")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f'Fetching config for "{username}"...',
        parse_mode="HTML",
    )

    config_list = await get_config_ezpz(username)

    if not config_list:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f'Could not retrieve config for "{username}". The user might not exist or there was a script error.',
            reply_markup=reply_markup,
        )
        return

    ipv6_pattern = r'"server":"[0-9a-fA-F:]+"'

    for config in config_list:
        if config.endswith("-ipv6") or re.search(ipv6_pattern, config):
            config_text = f"IPv6 Config:\n<pre>{config}</pre>"
        else:
            config_text = f"<pre>{config}</pre>"

        try:
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
        except Exception as e:
            print(
                f"Error generating QR or sending photo for config: {config}. Error: {e}"
            )
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"Could not generate QR code for the following config:\n{config_text}",
                parse_mode="HTML",
                reply_markup=reply_markup,
            )


@restricted
async def delete_user(
    update: Update, context: ContextTypes.DEFAULT_TYPE, username: str
):
    keyboard = []
    users = await get_users_ezpz()
    if len(users) == 1 and username in users:
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
async def approve_delete(
    update: Update, context: ContextTypes.DEFAULT_TYPE, username: str
):
    success = await delete_user_ezpz(username)
    keyboard = []
    keyboard.append([InlineKeyboardButton("Back", callback_data="start")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    if success:
        text = f"User {username} has been deleted."
    else:
        text = f"Failed to delete user {username}. Check bot logs for details."

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

    # Delete the message with the inline keyboard to avoid stale buttons
    if query.message:
        try:
            await query.message.delete()
        except Exception as e:
            print(f"Could not delete message: {e}")

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
    if len(response) > 1:
        action = response[0]
        username = response[1]

        if action == "show_user":
            await show_user(update, context, username)
        elif action == "delete_user":
            await delete_user(update, context, username)
        elif action == "approve_delete":
            await approve_delete(update, context, username)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"Unknown action: {action}",
            )


@restricted
async def user_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "expected_input" in context.user_data:
        expected_input = context.user_data["expected_input"]

        if expected_input == "username":
            username = update.message.text.strip()

            existing_users = await get_users_ezpz()
            if username in existing_users:
                await update.message.reply_text(
                    f'User "{username}" exists, try another username.'
                )
                await add_user(update, context)
                return

            if not username_regex.match(username):
                await update.message.reply_text(
                    "Username can only contain A-Z, a-z and 0-9, try another username."
                )
                await add_user(update, context)
                return

            success = await add_user_ezpz(username)

            if success:
                await update.message.reply_text(f'User "{username}" is created.')
                del context.user_data["expected_input"]
                await show_user(update, context, username)
            else:
                await update.message.reply_text(
                    f'Failed to create user "{username}". Check bot logs for details.'
                )
                del context.user_data["expected_input"]
                await start(update, context)
        else:
            print(f"Warning: Unknown expected_input state: {expected_input}")
            del context.user_data["expected_input"]
            await update.message.reply_text(
                "An unexpected state occurred. Returning to start."
            )
            await start(update, context)


def main():
    application = (
        Application.builder().token(token).arbitrary_callback_data(True).build()
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button, pattern=".*"))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, user_input))

    print("Bot started. Waiting for messages...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"Bot failed to start: {ex}")
