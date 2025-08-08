#!/usr/bin/env python3
import os, sys, json, time, random, re, sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "chatusers.db")


spam_patterns = [
    r"buy\s+now",
    r"free\s+money",
    r"fr[e3]{2}\s+m[o0]ney",
    r"click\s+here",
    r"cl[i1]ck\s+h[e3]re",
    r"subscribe\s+(now|today)",
    r"win\s+big",
    r"w[i1]n\s+b[i1]g",
    r"limited\s+offer",
    r"act\s+now",
    r"get\s+rich\s+quick",
    r"make\s+money\s+fast",
    r"easy\s+cash",
    r"work\s+from\s+home",
    r"double\s+your\s+income",
    r"guaranteed\s+results",
    r"risk[-\s]*free",
    r"lowest\s+price",
    r"no\s+credit\s+check",
    r"instant\s+approval",
    r"earn\s+\$\d+",
    r"cheap\s+meds",
    r"online\s+pharmacy",
    r"lose\s+weight\s+fast",
    r"miracle\s+cure",
    r"bitcoin\s+offer",
    r"b[i1]tcoin\s+deal",
    r"earn\s+bitcoin",
    r"make\s+money\s+with\s+bitcoin",
    r"crypto\s+investment",
    r"crypto\s+deal",
    r"get\s+rich\s+with\s+crypto",
    r"eth[e3]reum\s+promo",
    r"buy\s+crypto\s+now",
    r"invest\s+in\s+(crypto|bitcoin|ethereum)"
]

spam_patterns += [
    r"\bfree\s+(bitcoin|crypto|ethereum)\b",
    r"\bsell\s+(bitcoin|crypto|ethereum)\b",
    r"\bi\s+sell\s+(bitcoin|bitcoins|crypto|ethereum)\b",
    r"\bbuy\s+(bitcoin|crypto|ethereum)\b",
    r"\bget\s+(bitcoin|crypto|ethereum)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|crypto|ethereum)\b",
    r"\binvest\s+(in|into)\s+(bitcoin|crypto|ethereum)\b",
    r"\bbitcoin\s+(promo|deal|offer|discount)\b",
    r"\bcrypto\s+(promo|deal|offer|discount)\b"
]

spam_patterns += [
    r"\bfree\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\b(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\s+for\s+you\b",
    r"\bsell\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bbuy\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bi\s+sell\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bget\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\binvest\s+(in|into)\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b"
]

spam_patterns += [
    r"(?:\W|^)(bitcoin|bitcoins|crypto|ethereum|tokens|coins)(?:\W|$)",  # matches with punctuation or boundaries
    r"\b(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\s+for\s+(free|you)\b",
    r"\bfree\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b",
    r"\bget\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b"
]


# Recover input from environment variables
def recover_input(key_suffix):
    for k, v in os.environ.items():
        if k.lower().endswith(key_suffix):
            return v.strip()
    return ""

raw_username     = recover_input("username")
message          = recover_input("message")
remote_identity  = recover_input("remote_identity")
nickname         = recover_input("field_username")  # This is prioritized
dest             = recover_input("dest")

# Fallback to command-line arguments if needed
if not raw_username and len(sys.argv) > 1:
    raw_username = sys.argv[1].strip()
if not message and len(sys.argv) > 2:
    message = sys.argv[2].strip()
if not dest and len(sys.argv) > 3:
    dest = sys.argv[3].strip()

# Extract hash code from remote identity and LXMF address
hash_code = remote_identity[-4:] if remote_identity else ""
dest_code = dest[-4:] if dest else ""

# Smart fallback for display name
if nickname:
    display_name = nickname
elif dest:
    display_name = f"Guest_{dest_code}"
else:
    display_name = "Guest"

# os env print for debug test
#print("> Meshchat Environment Variables:\n")
#for key, value in os.environ.items():
#   print(f"{key} = {value}")

# os env print test to check recovered inputs
#print(f"[DEBUG] Recovered Inputs:")
#print(f"  Username        : {raw_username}")
#print(f"  Message         : {message}")
#print(f"  Nickname        : {nickname}")
#print(f"  Nickfieldname        : {field_nickname}")
#print(f"  Remote Identity : {remote_identity}")
#print(f"  Hash Code       : {hash_code}")
#print(f"  LXMF Code       : {dest_code}")
#print(f"  LXMF Address    : {dest}")
#print(f"  Display Name    : {display_name}")
#print("Using database at:", os.path.abspath(DB_PATH))

# sql db nick binding and recovering

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_identity TEXT,
            dest TEXT UNIQUE NOT NULL,
            display_name TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_display_name_from_db(dest):
    if not dest:
        return None
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT display_name FROM users WHERE dest = ?", (dest,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def save_user_to_db(remote_identity, dest, display_name):
    if not remote_identity or not dest:
        return  # Don't save if required info is missing
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (remote_identity, dest, display_name)
        VALUES (?, ?, ?)
        ON CONFLICT(dest) DO UPDATE SET
            remote_identity = excluded.remote_identity,
            display_name = excluded.display_name
    """, (remote_identity, dest, display_name))
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# Get environment variables
nickname = os.getenv("field_username", "").strip()
dest = os.getenv("dest", "").strip()
remote_identity = os.getenv("remote_identity", "").strip()

# Try to load display_name from DB
db_display_name = get_display_name_from_db(dest)

# Determine final display_name
if nickname:
    display_name = nickname
elif db_display_name:
    display_name = db_display_name
elif dest:
    display_name = f"Guest_{dest[-4:]}"
else:
    display_name = "Guest"

# Save user to DB if valid
save_user_to_db(remote_identity, dest, display_name)

# -----------------------------------------------

safe_username = (
    raw_username.replace("`", "").replace("<", "").replace(">", "")
    .replace("\n", "").replace("\r", "").replace('"', "").replace("'", "")
    .replace("/", "").replace("\\", "").replace(";", "").replace(":", "")
    .replace("&", "").replace("=", "").replace("{", "").replace("}", "")
    .replace("[", "").replace("]", "").replace("(", "").replace(")", "")
    .replace("\t", "").replace("*", "").replace("+", "").replace("%", "")
    .replace("#", "").replace("^", "").replace("~", "").replace("|", "")
    .replace("$", "").replace(" ", "").strip() or "Guest"
)

topic_file = os.path.join(os.path.dirname(__file__), "topic.json")
try:
    with open(topic_file, "r") as tf:
        topic_data = json.load(tf)
        topic_text = topic_data.get("text", "Welcome to the chatroom!")
        topic_author = topic_data.get("user", "System")
except:
    topic_text = "Welcome to the chatroom!"
    topic_author = "System"


log_file = os.path.join(os.path.dirname(__file__), "chat_log.json")
DISPLAY_LIMIT = 25
debug = []

try:
    with open(log_file, "r") as f:
        log = json.load(f)
        debug.append(f" Total {len(log)} messages")
except Exception as e:
    log = []
    debug.append(f"Failed to load log: {e}")

# Commands logic
cmd = message.strip().lower()
if safe_username == "4dm1n@@@" and cmd == "/clear":
    if log:
        removed = log.pop()
        debug.append(f"Removed last message: <{removed['user']}> {removed['text']}")
        try:
            with open(log_file, "w") as f:
                json.dump(log, f)
            debug.append("Log updated after clearing.")
        except Exception as e:
            debug.append(f"Clear error: {e}")
    else:
        debug.append("No messages to clear.")

elif safe_username == "4dm1n@@@" and cmd == "/clearall":
    if log:
        log.clear()
        debug.append("All messages cleared by admin.")
        try:
            with open(log_file, "w") as f:
                json.dump(log, f)
            debug.append("Log successfully emptied.")
        except Exception as e:
            debug.append(f"ClearAll error: {e}")
    else:
        debug.append("Log already empty. Nothing to clear.")

elif cmd == "/stats":
    user_stats = {}
    user_set = set()
    for msg in log:
        if msg["user"] != "System":
            user_stats[msg["user"]] = user_stats.get(msg["user"], 0) + 1
            user_set.add(msg["user"])
    
    total_users = len(user_set)
    total_messages = len(log)
    top_users = sorted(user_stats.items(), key=lambda x: x[1], reverse=True)

    # Prepare lines
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": "`!` Stats Report: `!` "})
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": f"`!` Total messages: {total_messages} `!` "})
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": f"`!` Total users: {total_users} `!` "})
    
    # Combine top chatters in one line
    top_line = "`!` Top chatters: `!` " + " , ".join([f"`!` {user} ({count} msg) `!`" for user, count in top_users[:5]])
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": top_line})

elif cmd == "/users":
    # Count messages per user
    from collections import Counter
    user_counts = Counter(msg["user"] for msg in log if msg["user"] != "System")

    # Sort by most active
    sorted_users = sorted(user_counts.items(), key=lambda x: -x[1])
    total_users = len(sorted_users)

    # Header line
    log.append({
        "time": time.strftime("[%H:%M:%S]"),
        "user": "System",
        "text": f"`!` Active Users List and Stats, Total Users: ({total_users}) `! "
    })

    # Show in chunks of N with message counts
    for i in range(0, total_users, 6):
        chunk = ", ".join(f"`!` {user} `!({count}msg)" for user, count in sorted_users[i:i+6])
        log.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": "System",
            "text": chunk
        })

elif cmd == "/help":
    help_lines = [
        "`!` Chatroom Commands:`!`",
        "`!` /info`!` : Show The Chat Room! Informations, Usage and Disclaimer",
        "`!` /help`!` : Show all the available user commands",
        "`!` /stats`!` : Show chatroom statistics, including Top 5 Chatters",
        "`!` /users`!` : List all chatroom users",
        "`!` /topic`!` : Show or Change Room Topic, usage: '/topic' or '/topic Your New Topic Here' ",
        "`!` /time`!` : Show current server and user time",
        "`!` /ping`!`: Reply with PONG! if the chat system is up and working",
        "`!` /lastseen <username>`!`: Last seen user info and latest user message",
        "`!` /version`!`: Show chatroom version",

    ]
    for line in help_lines:
        log.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": "System",
            "text": line
        })

elif cmd == "/info":
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
    for line in info_lines:
        log.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": "System",
            "text": line
        })


elif cmd == "/time":
    server_time = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        import pytz, datetime
        user_time = datetime.datetime.now(pytz.timezone("Europe/Rome")).strftime("%Y-%m-%d %H:%M:%S")
    except:
        user_time = "(Local time not available)"
    time_text = f"Server time: {server_time} // User time (Naples): {user_time}"
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": time_text})

elif cmd == "/version":
    version_text = "The Chat Room v1.3b // Powered by Reticulum NomadNet // IRC Style // Optimized for Meshchat // Made by F."
    version_text2 = "This chat is running on a VPS server, powered by RNS v1.0.0 and Nomadnet v.0.8.0."
    version_text3 = "Latest Implementations in v1.3b: AntiSpam Filter,"
    version_text4 = "Nickname persistency with lxmf binding (Thanks To: Thomas!!)"

    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": version_text})
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": version_text2})
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": version_text3})
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": version_text4})


elif cmd.startswith("/lastseen "):
    target_user = cmd[10:].strip()
    last = next((msg for msg in reversed(log) if msg["user"] == target_user), None)
    seen_text = f"Last seen {target_user} at {last['time']}: {last['text']}" if last else f"No record of user '{target_user}'."
    log.append({"time": time.strftime("[%H:%M:%S]"), "user": "System", "text": seen_text})

elif cmd.startswith("/topic "):
    new_topic = message[7:].replace("`", "").strip()
    if new_topic:
        trimmed_topic = new_topic[:70]  # limit to N characters
        timestamp = time.strftime("%d %B %Y")
        topic_data = {"text": trimmed_topic, "user": safe_username, "time": timestamp}
        try:
            with open(topic_file, "w") as tf:
                json.dump(topic_data, tf)
            log.append({
                "time": time.strftime("[%H:%M:%S]"),
                "user": "System",
                "text": f"Topic set by {safe_username} on {timestamp}: {trimmed_topic} `!`[<Reload Page!>`:/page/index.mu`username]`!"
            })
        except Exception as e:
            debug.append(f"Topic update error: {e}")
    else:
        debug.append("No topic text provided.")

elif cmd == "/topic":
    log.append({
        "time": time.strftime("[%H:%M:%S]"),
        "user": "System",
        "text": f"Current Topic: {topic_text} (set by {topic_author} on {topic_data.get('time')})"
    })

elif cmd == "/ping":
    log.append({
        "time": time.strftime("[%H:%M:%S]"),
        "user": "System",
        "text": "PONG! (System is up and working!)"
    })

elif raw_username and message and message.lower() != "null":
    sanitized_message = message.replace("`", "")  # remove backticks to prevent formatting issues

    # 🔍 Spam detection logic
    banned_words = ["buy now", "free money", "click here", "subscribe", "win big", "limited offer", "act now"]
    is_spam = any(re.search(pattern, sanitized_message.lower()) for pattern in spam_patterns)

    if is_spam:
        # 🚫 Don't write to JSON, just log the system message
        log.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": "System",
            "text": "Spam Detected! Message Blocked!"
        })
        debug.append(f" Spam blocked from '{safe_username}'")
    else:
        # ✅ Normal message flow
        log.append({
            "time": time.strftime("[%H:%M:%S]"),
            "user": safe_username,
            "text": sanitized_message
        })
        try:
            with open(log_file, "w") as f:
                json.dump(log, f)
            debug.append(f" Message by '{safe_username}' sent!")
        except Exception as e:
            debug.append(f" Send error: {e}")
else:
    debug.append(" Skipped sending: Missing username or message")


# Color system
colors = [
    "B900", "B090", "B009", "B099", "B909", "B066", "B933", "B336", "B939",
    "B660", "B030", "B630", "B363", "B393", "B606", "B060", "B003", "B960", "B999",
    "B822", "B525", "B255", "B729", "B279", "B297", "B972", "B792", "B227", "B277",
    "B377", "B773", "B737", "B003", "B111", "B555", "B222", "B088", "B808", "B180"
]
def get_color(name):
    return colors[sum(ord(c) for c in name.lower()) % len(colors)]

# Output UI
template = "> `!` >>> THE CHAT ROOM! <<<   `F009` Powered by Reticulum / NomadNet - IRC Style - Free Global Chat Room - Optimized for Meshchat - v1.3b `F `!` \n"
template += "-"
template += f"\n`Fe0f`!` ########## Room Topic: {topic_text} `! (Set by: {topic_author}, {topic_data.get('time')}) `!` ########## `!`f \n"
template += "-\n"
for msg in log[-DISPLAY_LIMIT:]:
    color = get_color(msg["user"])
    template += f"[{msg['time']} `{color}` `!` `*` <{msg['user']}>`b `! `*` {msg['text']}\n"
template += "-"
# sanitize and read name from display_name os env
safe_display_name = display_name.replace("`", "'")
template += f"\n>`!` Nickname: `Baaa`F000`<13|username`{safe_display_name}>`b`F"

template += f"   Message: `B999`<57|message`>`b"
template += " `[  <Send message>`:/page/index.mu`username|message]`!  `!`[<Reload Page>`:/page/index.mu`username]`!\n"

template += "-"
template += f"\n`B222`Fe0f` User commands: /info, /help, /stats, /users, /lastseen <user>, /topic, /time, /version    `b`F   `Baaa`F000` `!` Total Messages: {len(log)} `[<Read Full ChatLog>`:/page/fullchat.mu]`!`b`f`f"
template += "\n-"
template += f"\n\n `B222`F90f` Note: To save your nickname (persistency across sessions), set your nickname and press the fingerprint button on MeshChat! \n        To recover it on new sessions (only if it doesn't appear due to lost fingerprint) just press it again!`b`f`"
print(template)
