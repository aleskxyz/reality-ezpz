import os
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, ConversationHandler
import re
import subprocess

token = os.environ['BOT_TOKEN']
admin = os.environ['BOT_ADMIN']
updater = Updater(token)
username_regex = re.compile("^[a-zA-Z0-9]+$")
command = 'bash <(curl -sL https://raw.githubusercontent.com/aleskxyz/reality-ezpz/master/reality-ezpz.sh) '
def get_users_ezpz():
  local_command = command + '--list-users'
  return run_command(local_command).split('\n')[:-1]
def get_config_ezpz(username):
  local_command = command + f'--show-user {username} | grep vless://'
  return run_command(local_command)
def delete_user_ezpz(username):
  local_command = command + f'--delete-user {username}'
  run_command(local_command)
  return
def add_user_ezpz(username):
  local_command = command + f'--add-user {username}'
  run_command(local_command)
  return

def run_command(command):
  process = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output, _ = process.communicate()
  return output.decode()

def restricted(func):
  def wrapped(update, context, *args, **kwargs):
    username = None
    if update.message:
      username = update.message.chat.username
    elif update.callback_query and update.callback_query.message:
      username = update.callback_query.message.chat.username
    admin_list = admin.split(',')
    if username in admin_list:
      return func(update, context, *args, **kwargs)
    else:
      context.bot.send_message(chat_id=update.effective_chat.id, text='You are not authorized to use this bot.')
  return wrapped

@restricted
def start(update, context):
  commands_text = "Reality-EZPZ User Management Bot\n\nChoose an option:"
  keyboard = [
    [InlineKeyboardButton('Show User', callback_data='show_user')],
    [InlineKeyboardButton('Add User', callback_data='add_user')],
    [InlineKeyboardButton('Delete User', callback_data='delete_user')],
  ]
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.bot.send_message(chat_id=update.effective_chat.id, text=commands_text, reply_markup=reply_markup)

@restricted
def users_list(update, context, text, callback):
  keyboard = []
  for user in get_users_ezpz():
    keyboard.append([InlineKeyboardButton(user, callback_data=f'{callback}!{user}')])
  keyboard.append([InlineKeyboardButton('Back', callback_data='start')])
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)

@restricted
def show_user(update, context, username):
  text = get_config_ezpz(username)
  keyboard = []
  keyboard.append([InlineKeyboardButton('Back', callback_data='show_user')])
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.bot.send_message(chat_id=update.effective_chat.id, text=f'Config for "{username}":')
  context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)

@restricted
def delete_user(update, context, username):
  keyboard = []
  if len(get_users_ezpz()) == 1:
    text = 'You cannot delete the only user.\nAt least one user is needed.\nCreate a new user, then delete this one.'
    keyboard.append([InlineKeyboardButton('Back', callback_data='start')])
    reply_markup = InlineKeyboardMarkup(keyboard)
    context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)
    return
  text = f'Are you sure to delete "{username}"?'
  keyboard.append([InlineKeyboardButton('Delete', callback_data=f'approve_delete!{username}')])
  keyboard.append([InlineKeyboardButton('Cancel', callback_data='delete_user')])
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)

@restricted
def add_user(update, context):
  text = 'Enter the username:'
  keyboard = []
  keyboard.append([InlineKeyboardButton('Cancel', callback_data='cancel')])
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.user_data['expected_input'] = 'username'
  context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)

@restricted
def approve_delete(update, context, username):
  delete_user_ezpz(username)
  text = f'User {username} has been deleted.'
  keyboard = []
  keyboard.append([InlineKeyboardButton('Back', callback_data='start')])
  reply_markup = InlineKeyboardMarkup(keyboard)
  context.bot.send_message(chat_id=update.effective_chat.id, text=text, reply_markup=reply_markup)

@restricted
def cancel(update, context):
  if 'expected_input' in context.user_data:
    del context.user_data['expected_input']
  start(update, context)

@restricted
def button(update, context):
  query = update.callback_query
  query.answer()
  response = query.data.split('!')
  if len(response) == 1:
    if response[0] == 'start':
      start(update, context)
    elif response[0] == 'cancel':
      cancel(update, context)
    elif response[0] == 'show_user':
      users_list(update, context, 'Select user to view config:', 'show_user')
    elif response[0] == 'delete_user':
      users_list(update, context, 'Select user to delete:', 'delete_user')
    elif response[0] == 'add_user':
      add_user(update, context)
    else:
      context.bot.send_message(chat_id=update.effective_chat.id, text='Button pressed: {}'.format(response[0]))
  if len(response) > 1:
    if response[0] == 'show_user':
      show_user(update, context, response[1])
    if response[0] == 'delete_user':
      delete_user(update, context, response[1])
    if response[0] == 'approve_delete':
      approve_delete(update, context, response[1])

@restricted
def user_input(update, context):
  if 'expected_input' in context.user_data:
    expected_input = context.user_data['expected_input']
    del context.user_data['expected_input']
    if expected_input == 'username':
      username = update.message.text
      if username in get_users_ezpz():
        update.message.reply_text(f'User "{username}" exists, try another username.')
        add_user(update, context)
        return
      if not username_regex.match(username):
        update.message.reply_text('Username can only contains A-Z, a-z and 0-9, try another username.')
        add_user(update, context)
        return
      add_user_ezpz(username)
      update.message.reply_text(f'User "{username}" is created.')
      show_user(update, context, username)

start_handler = CommandHandler('start', start)
button_handler = CallbackQueryHandler(button)

updater.dispatcher.add_handler(start_handler)
updater.dispatcher.add_handler(button_handler)
updater.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, user_input))

updater.start_polling()
updater.idle()
