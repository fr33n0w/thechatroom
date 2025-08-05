# commands.py

import time
import json
import os
from collections import Counter

# Topic storage path (can be configured as needed)
topic_file = os.path.join(os.path.dirname(__file__), "topic.json")

def cmd_clear(log, safe_username):
    debug = []
    if log:
        removed = log.pop()
        debug.append(f"Removed last message: <{removed['user']}> {removed['text']}")
        try:
            with open(os.path.join(os.path.dirname(__file__), "chat_log.json"), "w") as f:
                json.dump(log, f)
            debug.append("Log updated after clearing.")
        except Exception as e:
            debug.append(f"Clear error: {e}")
    else:
        debug.append("No messages to clear.")
    return log, debug

def cmd_clearall(log):
    debug = []
    if log:
        log.clear()
        debug.append("All messages cleared by admin.")
        try:
            with open(os.path.join(os.path.dirname(__file__), "chat_log.json"), "w") as f:
                json.dump(log, f)
            debug.append("Log successfully emptied.")
        except Exception as e:
            debug.append(f"ClearAll error: {e}")
    else:
        debug.append("Log already empty. Nothing to clear.")
    return log, debug

def cmd_stats(log):
    entries = []
    user_stats = {}
    user_set = set()
    for msg in log:
        if msg["user"] != "System":
            user_stats[msg["user"]] = user_stats.get(msg["user"], 0) + 1
            user_set.add(msg["user"])
    total_users = len(user_set)
    total_messages = len(log)
    top_users = sorted(user_stats.items(), key=lambda x: x[1], reverse=True)

    entries.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": "`!` Stats Report: `!`"})
    entries.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": f"`!` Total messages: {total_messages} `!`"})
    entries.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": f"`!` Total users: {total_users} `!`"})

    top_line = "`!` Top chatters: `!` " + " , ".join([f"`!` {user} ({count} msg) `!`" for user, count in top_users[:5]])
    entries.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": top_line})
    return entries

def cmd_users(log):
    entries = []
    user_counts = Counter(msg["user"] for msg in log if msg["user"] != "System")
    sorted_users = sorted(user_counts.items(), key=lambda x: -x[1])
    total_users = len(sorted_users)

    entries.append({
        "time": time.strftime("[%H:%M:%S]"),
        "user": "System",
        "text": f"`!` Active Users List and Stats, Total Users: ({total_users}) `!"
    })

    for i in range(0, total_users, 6):
        chunk = ", ".join(f"`!` {user} `!({count}msg)" for user, count in sorted_users[i:i+6])
        entries.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": "System",
            "text": chunk
        })
    return entries

def cmd_help():
    help_lines = [
        "`!` Chatroom Commands:`!`",
        "`!` /info`!` : Show The Chat Room! Informations, Usage and Disclaimer",
        "`!` /help`!` : Show all the available user commands",
        "`!` /stats`!` : Show chatroom statistics, including Top 5 Chatters",
        "`!` /users`!` : List all chatroom users",
        "`!` /topic`!` : Show or Change Room Topic, usage: '/topic' or '/topic Your New Topic Here'",
        "`!` /time`!` : Show current server and user time",
        "`!` /ping`!` : Reply with PONG! if the chat system is up and working",
        "`!` /lastseen <username>`!` : Last seen user info and latest user message",
        "`!` /version`!` : Show chatroom version",
    ]
    return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": line} for line in help_lines]

def cmd_info():
    info_lines = [
        "`!` The Chat Room Info - Overview - Usage - Commands - Disclaimer - README! :) `!`",
        "Welcome! This space is designed to connect people through an old school irc-styled interface.",
        "No registration required, set your nickname and you are ready to message with other users.",
        "Nicknames are randomly colorized and there is persistent color for every nickname.",
        "No privacy compromission: use any nick you want. Nothing is recorded or associated to your rns identity.",
        "This runs on a Nomadnet, so it will be visible internationally. Respect all the user languages in chat.",
        "This chat is based on micron and python components.",
        "ChatRoom script is running on a VPS server so it will be stable and always online",
        "You can send irc-style messages and use various commands to explore the chatroom.",
        "`!` Command Reference `!`",
        "Just Some Examples:",
        "/users : show active users and message counts",
        "/lastseen <username> : check a user's recent activity",
        "/topic : show or change the room topic",
        "/stats : show chat stats including top chatters",
        "`!` Use /help to view the full list of available commands. `!`",
        "`!` Technical Notes `!`",
        "Due to micron limitations, the chatroom does not refresh automatically.",
        "To see new messages or preserve your nickname, reload the page using the provided link buttons.",
        "Refreshing the page using meshchat browser function will remove nickname persistance, so use our Reload button",
        "The main chatroom shows the last 30 messages; use the button at the bottom to view the full chat log.",
        "`!` DISCLAIMER `!`",
        "This chatroom is a space for connection, collaboration, and respectful interaction.",
        "Rude, offensive, or inappropriate behavior is not tolerated. Messages may be deleted.",
        "Suspension or message deletion can occur without prior warning in serious or repeated cases.",
        "`!` BEFORE FREE SPECH, COMES RESPECT! - WELCOME TO >>THE CHAT ROOM!<< `!`"
    ]
    return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": line} for line in info_lines]

def cmd_time():
    server_time = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        import pytz, datetime
        user_time = datetime.datetime.now(pytz.timezone("Europe/Rome")).strftime("%Y-%m-%d %H:%M:%S")
    except:
        user_time = "(Local time not available)"
    time_text = f"Server time: {server_time} // User time (Naples): {user_time}"
    return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": time_text}]

def cmd_version():
    return [
        {"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": "The Chat Room v1.2b // Powered by Reticulum NomadNet // IRC Style // Optimized for Meshchat // Made by F."},
        {"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": "This chat is running on a VPS server, powered by RNS v1.0.0 and Nomadnet v.0.8.0."}
    ]

def cmd_lastseen(log, target_user):
    last = next((msg for msg in reversed(log) if msg["user"] == target_user), None)
    seen_text = f"Last seen {target_user} at {last['time']}: {last['text']}" if last else f"No record of user '{target_user}'."
    return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": seen_text}]

def cmd_topic_get():
    try:
        with open(topic_file, "r") as tf:
            topic_data = json.load(tf)
        return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": f"Current Topic: {topic_data.get('text')} (set by {topic_data.get('user')} on {topic_data.get('time')})"}]
    except:
        return [{"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": "No topic data available."}]

def cmd_topic_set(new_topic, safe_username):
    trimmed_topic = new_topic[:70]
    timestamp = time.strftime("%d %B %Y")
    topic_data = {"text": trimmed_topic, "user": safe_username