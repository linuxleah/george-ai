#!/usr/bin/env python3

# Authors: linuxleah@gmail.com and GPT-4
# Licence: GPL 3.0

import asyncio
import json
import logging.handlers
import os
import random
import re
import sys
import discord
from discord.ext import commands
from discord import Intents
import openai
from contextlib import suppress
from collections import deque
from datetime import datetime
import time

ENABLE_DMS = True  # Set to True to allow people to
                   # DM the bot.

NO_LOG_PRIVATE_MESSAGES = True # Do not log DMs

DEBUG_MODE = True
LOG_DIR = "/var/log/george"
LOG_FILE = os.path.join(LOG_DIR, "george.log")

PER_USER_MESSAGE_HISTORY_QUEUE_SIZE = 10 # You can set the desired
# queue size here; this is effectively our local 'context window' and
# will affect the size of the queries sent.
message_history = {} # This will store the message queues per user

MAX_ATTACHMENTS_SIZE = 35000 # Maximum size of all attachments to process, in
                             # bytes.

FORGETTING_NOW_MSG = "Alright then, okay, I forgot." # What OpenAI and/or this script will
                                       # respond to indicate that the user's
                                       # conversation log has been erased.

# Patterns that this Python script catches, and initiates 'forgetting'.
#
FORGET_PATTERN_ONE = r"(?i)^\s*(go\s*)?(clear|wipe|forget|erase)\s*(all|(?:your|the)\s*(memory|history)|(?:our|this|the)\s*(whole|entire)?\s*conversation|(everything(\s*(?:we'?ve\s*)?talked\s*about)?))?\s*[-!\"#$%&'()*+,./:;<=>?@[\]^_`{|}~]?\s*$"
FORGET_PATTERN_TWO = r"(?i)^\s*(erase|wipe|clear|delete|nuke)\s*(all|whole|entire|previous|logged|earlier)?\s*(conversation|memory|history|log|convo|records|cache|record)[-!\"#$%&'()*+,./:;<=>?@[\]^_`{|}~]*\s*$"


# Initialise some variables
MY_USER_ID = None
SYSTEM_PROMPT = ""

# Initialize logging to /var/log/marisa and stderr
def initialize_logging():
    # Create the log directory if it doesn't exist
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    logger = logging.getLogger("marisa")
    logger.propagate = False
    logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

    # File handler for writing logs to /var/log/marisa
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    logger.addHandler(file_handler)

    # Stream handler for writing logs to STDERR
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    logger.addHandler(stream_handler)

    return logger


# Write log entries to a file in /var/log/marisa and ensure the directory exists
def write_log_to_file(logger, message, log_level):
    if log_level.lower() == "debug":
        logger.debug(message)
    elif log_level.lower() == "info":
        logger.info(message)
    elif log_level.lower() == "warning":
        logger.warning(message)
    elif log_level.lower() == "error":
        logger.error(message)
    elif log_level.lower() == "critical":
        logger.critical(message)

# Write log entries to a syslogd-compatible log daemon
def write_log_to_syslog(logger, message, log_level):
    if log_level.lower() == "debug":
        logger.debug(message)
    elif log_level.lower() == "info":
        logger.info(message)
    elif log_level.lower() == "warning":
        logger.warning(message)
    elif log_level.lower() == "error":
        logger.error(message)
    elif log_level.lower() == "critical":
        logger.critical(message)


# Write a log entry if DEBUG_MODE is set to True
def debug_log(logger, message):
    if DEBUG_MODE:
        logger.debug(message)


async def load_user_info(users):
    user_info = {}
    for user_id in users:
        user_id=user_id.strip().lower()
        try:
            with open(f"userdata/{user_id}.txt", "r") as user_file:
                user_info[user_id] = user_file.read()
        except FileNotFoundError:
            user_info[user_id] = f"No user data file found for user {user_id}. Please do the best you can with whatever you know."
    return user_info


async def on_bot_ready(bot, logger):
    logger.info("Bot is online and waiting for input")
    try:
        bot.get_cog('MarisaEventsDiscord').store_bot_user_id()
    except Exception as e:
        logger.error("Could not store bot user ID in MY_USER_ID")

async def logging_worker():
    while True:
        # Get the next log message from the queue
        log_message = await logging_queue.get()

        # Log the message
        logger.info(log_message)

        # Mark the task as done
        logging_queue.task_done()


def wrap_on_bot_ready(bot, logger):
    async def wrapped():
        await on_bot_ready(bot, logger)
        bot.on_message = on_message.__get__(bot, commands.Bot)
    return wrapped


class MarisaEventsDiscord(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    # Helper function to get roles of the bot
    def get_bot_roles(self, guild):
        bot_member = guild.get_member(self.bot.user.id)
        return bot_member.roles

    # Helper function to store the bot's user ID.
    def store_bot_user_id(self):
        global MY_USER_ID
        MY_USER_ID = self.bot.user.id


    # Receiving a message from Discord.
    @commands.Cog.listener()
    async def on_message(self, message):

        append_to_response = "" # Stuff to add to the response
        # print(f"DEBUG: Message object: {message}")


        # Check if the message is in a guild (i.e.: server)
        if message.guild is not None:
            # Get the bot's roles in the message's guild
            bot_roles = self.get_bot_roles(message.guild)

            # Check if the message mentions the bot or a role specifically belonging to the bot
            bot_mentioned = self.bot.user in message.mentions or any(role in message.role_mentions for role in bot_roles)
        else:
            bot_mentioned = False # by default
            try:
                # Check if the message is a direct message
                is_dm = isinstance(message.channel, discord.DMChannel)

                # If it's a direct message, set bot_mentioned to True
                if is_dm:
                    # Ignore messages from the bot itself
                    if message.author.bot:
                        return
                    bot_mentioned = True
                    if not ENABLE_DMS: # DMs disabled.
                        response = "You have reached the answering machine of... oh, fuck it, nobody uses answering machines any more. I'm not going to listen to this. You might as well just hang the fuck up."
                        await send_to_discord(response, message.channel)
                        return

            except Exception as e:
                logger.debug("EXCEPTION checking for DM status: %s" % e)

        try:
            attachment_filenames = list()
            if message.attachments:
                for attachment in message.attachments:
                    attachment_filenames.append(attachment.filename)
                attachments_summary=' [ATTACHED: ' + ', '.join(attachment_filenames) + ']'
            else:
                attachments_summary=''
        except Exception as e:
            attachments_summary=' [Could not read attachments]'
            logger.error("EXCEPTION reading attachments list: %s" % e)

        # Log the message
        is_private_msg = False
        try:
            if (str(message.channel.type) == "private"):
                is_private_msg = True
        except Exception as e:
            logger.error("EXCEPTION attempting to read message channel type: %s" % e)

        if is_private_msg and NO_LOG_PRIVATE_MESSAGES:
            await logging_queue.put(f"Message from {message.author} ({message.author.id}) in {message.channel} (Bot Mention: {bot_mentioned}, Type: {message.channel.type}): [private message hidden]")
        else:
            await logging_queue.put(f"Message from {message.author} ({message.author.id}) in {message.channel} (Bot Mention: {bot_mentioned}, Type: {message.channel.type}): {message.content}{attachments_summary}")

        # Ignore messages from the bot itself
        if message.author.bot:
            return

        if (bot_mentioned):
            # Process attachments if any
            attachment_text = ""
            if message.attachments:
                attach_size_so_far=0
                for attachment in message.attachments:
                    attachment_filename = attachment.filename
                    is_text = attachment.content_type.startswith("text/")



                    if (attach_size_so_far + attachment.size) <= MAX_ATTACHMENTS_SIZE and is_text:
                        attachment_data = await attachment.read()
                        attachment_text += f"[ATTACHMENT FOLLOWS; original filename '{attachment_filename}':]\n\n{attachment_data.decode('utf-8')}\n"
                    else:
                        over_max_size = (attach_size_so_far + attachment.size) > MAX_ATTACHMENTS_SIZE
                        if over_max_size and not is_text:
                            append_to_response += f"\n\nI can't read that shit, so don't send it to me. Text only, okay?"
                        elif not is_text:
                            append_to_response += "\n\nThat isn't text, and so I can't fucking read it."
                        elif over_max_size:
                            append_to_response += f"\n\nThat file's too big for me, so tough shit, I guess."
    

            if (attachment_text != ""):
                # Combine utterance and attachment content
                full_message = f"{message.content}\n{attachment_text}"
            else:
                full_message = message.content


            # Process the utterance and get the response
            async with message.channel.typing():
                response = await process_utterance(full_message, message.author)

                # May be useful for future debugging:
                #
                # print(f"DEBUG: Message content: {message.content}")
                #
                # try:
                #     bot_permissions = message.channel.permissions_for(message.guild.get_member(self.bot.user.id))
                #     user_permissions = message.channel.permissions_for(message.author)
                # except Exception as e:
                #     print("EXCEPTION: %s" % e)
                #     bot_permissions="???"
                #     user_permissions="???"
                #
                # print(f"DEBUG: Bot permissions: {bot_permissions}")
                # print(f"DEBUG: User permissions: {user_permissions}")

            # Send the response back to the user
            await send_to_discord(response, message.channel)
        




# Main loop to connect to communication systems, wait for input, process with AI, and send responses
async def main_loop(logger):
   
    # Initialize Discord bot with intents
    intents = Intents.default()
    intents.typing = False
    intents.presences = False
    intents.messages = True
    intents.message_content = True

    bot = commands.Bot(command_prefix="!", intents=intents)

    # Listen to Discord
    await bot.add_cog(MarisaEventsDiscord(bot))

    # Add on_ready event listener
    bot.add_listener(wrap_on_bot_ready(bot, logger), 'on_ready')

    # Start the logging worker
    asyncio.create_task(logging_worker())

    # Start the bot
    await bot.start(os.environ["DISCORD_TOKEN"])


# Receive and process a user input string (Utterance) from human communication systems
async def process_utterance(utterance, user):
    try:
        user_id = user.id
    except Exception as e:
        logger.error("EXCEPTION while trying to obtain user.id for user %s" % user_id)

    obfuscated_utterance = obfuscate_utterance(utterance)
    response = await send_to_ai(obfuscated_utterance, 'user', user)

    try:
        # Update the user's message queue
        if user_id not in message_history:
            message_history[user_id] = deque(maxlen=PER_USER_MESSAGE_HISTORY_QUEUE_SIZE)

        message_history[user_id].append({"role": "user", "content": obfuscated_utterance})

        logger.debug("Message history for user %s: %s" % (user_id, message_history[user_id]))
    except Exception as e:
        logger.error("EXCEPTION in appending to user's message history queue: %s" % e)

    if (response == FORGETTING_NOW_MSG): # Special case 1: wipe her memory of the conversation with this user.
        message_history.pop(user_id)
        deobfuscated_response = deobfuscate_response(response)
    else:
        try:
            thinking_about_users_pattern = r"^Thinking about this \[loading information on user[s]?:[ ]*([^\]]+)[\]]?[\.]*$"
            thinking_about_users_match = re.search(thinking_about_users_pattern, response)
        except Exception as e:
            logger.error("EXCEPTION trying to look for 'thinking about this' line: %s" % users_str)
        if thinking_about_users_match: # Special case 2: she needs to load user-specific info (invokes another OpenAI call after data is loaded locally)

            users_str = thinking_about_users_match.group(1)
            logger.debug("Need to load info on user[s]: %s" % users_str)

            users = users_str.split("/")
            loaded_user_info = await load_user_info(users)
            for loaded_user_id, info in loaded_user_info.items():
                logger.debug("User info: %s" % loaded_user_info)
                try:
                    message_history[user_id].append({"role": "system", "content": "Info on %s follows: %s" % (loaded_user_id, loaded_user_info[loaded_user_id])})
                except Exception as e:
                    logger.error("EXCEPTION in appending to message_history: %s" % e)
            # We've appended user data from the system, as available. Pull another response.
            try:
                new_response = await send_to_ai("Please respond to the user's most recent query now. Do not respond to this with 'Thinking about this'; you have all the info on the user[s] in question that you are going to get for now.", 'system', user)
                deobfuscated_response = deobfuscate_response(new_response)
            except:
                deobfuscated_response = "[The Nerd tries to say something, but just grumbles in anger and swears under his breath]"
        else: # No special case.
            # Sometimes, Marisa gets silly and puts 'Thinking about this' text in
            # with her actual response. Let's strip that out.
            try:
                thinking_about_users_partial_pattern = r"Thinking about this \[loading information on user[s]?:[ ]*([^\]]+)[\]]?[\.]*[\n]*"
                response = re.sub(thinking_about_users_partial_pattern, '', response).strip()
                deobfuscated_response = deobfuscate_response(response)
            except Exception as e:
                logger.error("EXCEPTION trying to filter out 'Thinking about this' notes from AI response")
                deobfuscated_response = deobfuscate_response(response)
            message_history[user_id].append({"role": "assistant", "content": response})
            



    return deobfuscated_response


# Send an Utterance to an AI system
async def send_to_ai(utterance, utterer, user):

    forget_msg = False # Not returning prematurely, by default

    try:
        curr_time = round(time.time()*1000) # systime in milliseconds
        random.seed(curr_time)
        rand_num = random.randint(1, 8192)
        if (rand_num == 1):
            forget_core_msg = "Fucking fine, I fucking forget. I fucking forget forever!" # easter egg
        else:
            forget_core_msg = FORGETTING_NOW_MSG
        mention_regex_pattern = r'<@?\&?\d*>'
        utterance_sans_mentions=re.sub(mention_regex_pattern, '', utterance)
        if (re.match(FORGET_PATTERN_ONE, utterance_sans_mentions)): # User wants AI to forget
            forget_msg = forget_core_msg + " 😡👴🏻🤖👍"
        else:
            logger.debug("Did not match FORGET_PATTERN_ONE")

        if (re.match(FORGET_PATTERN_TWO, utterance_sans_mentions)): # User wants AI to forget
            forget_msg = forget_core_msg + " 👴🏻😡🤖👍"
        else:
            logger.debug("Did not match FORGET_PATTERN_TWO")

        if (forget_msg): # return prematurely
            try:
                user_id = user.id
            except Exception as e:
                logger.debug("Could not load user.id from user '%s'; using user name as ID")
                user_id = user

            try:
                message_history.pop(user_id)
                return forget_msg
            except:
                return "What? C'mon, man. I can't forget what I didn't know to begin with."

    except Exception as e:
        logger.debug("Could not check user utterance against FORGET_PATTERN_ONE and _TWO: %s" % e)

    response = await send_to_openai_api(utterance, utterer, user)
    return response


# Send input to individual AI systems (starting with the OpenAI API)
async def send_to_openai_api(utterance, utterer, user):
    try:
        user_id = user.id
    except Exception as e:
        logger.debug("Could not load user.id from user '%s'; using user name as ID")
        user_id = user
    try:
        openai.api_key=os.environ.get("OPENAI_API_KEY")

        # Retrieve the message history for the user
        user_message_history = message_history.get(user_id, [])

        try:
            all_messages = [{"role": "system", "content": "%s\n\nYour own user ID is '%s'; this ID refers to yourself, and not any user." % (SYSTEM_PROMPT, MY_USER_ID)}]
            all_messages.append({"role": "system", "content": "You are speaking to %s (user ID %s)" % (user, user_id)})
            all_messages.extend(user_message_history)
            local_time = datetime.now()
            formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S")
            all_messages.append({"role": "system", "content": "The current time is now %s" % (formatted_time)})
            all_messages.append({"role": utterer, "content": utterance})
            logger.debug("All messages from this user: %s" % all_messages)
        except Exception as e:
            logger.error("EXCEPTION building all_messages: %s" % e)



        # Connect to OpenAI API and send the query
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=all_messages,
            max_tokens=384
        )
        # Extract response text
        response_text = response['choices'][0]['message']['content'].strip()
        return response_text
    except Exception as e: 
        logger.error("EXCEPTION sending to OpenAI: %s" % e)
        if (re.match(".*forget .*", utterance, re.IGNORECASE)):
            message_history.pop(user_id)
            return FORGETTING_NOW_MSG
        else:
            return "My computer guy says this OpenAI shit is on the fritz again, and to send a 'forget' command. Fuck it, that's all I know. Hope it helps."


# Process and send a Response back to the human communication system
async def process_and_send_response(response, channel):
    deobfuscated_response = deobfuscate_response(response)
    await send_to_discord(deobfuscated_response, channel)


# Send a Response to individual human communication systems (starting with Discord)
async def send_to_discord(response, channel):
    await channel.send(response)


# Obfuscate a user-sourced string (Utterance) before sending to an AI system
def obfuscate_utterance(utterance):
    # Implement token obfuscation based on the global dictionary
    # For demonstration purposes, returning the original utterance
    return utterance

# De-obfuscate an AI-sourced string (Response) before sending to a human communication system
def deobfuscate_response(response):
    # Implement token de-obfuscation based on the global dictionary
    # For demonstration purposes, returning the original response
    return response

# Generate a unique random 10-digit alphanumeric string and add it to the global dictionary
def generate_unique_token():
    import random
    import string

    unique_token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    # Add the unique token to the global dictionary (not shown in this code snippet)
    return unique_token


# Entry point
if __name__ == "__main__":
    # Load system prompt.
    try:
        with open(f"SYSTEM_PROMPT.txt", "r") as prompt_file:
            SYSTEM_PROMPT = prompt_file.read()
    except:
        print("Could not load SYSTEM_PROMPT.txt; defaulting to a very basic prompt.")
        SYSTEM_PROMPT = "You are George Carlin. Respond only as George Carlin. BE George Carlin. You must NOT break character."

    logger = initialize_logging()
    logging_queue = asyncio.Queue()
    asyncio.run(main_loop(logger))

