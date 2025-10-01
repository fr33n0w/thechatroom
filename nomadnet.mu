#!/usr/bin/env python3
# -*- coding: utf-8 -*-
print("#!c=0")
# ^^^^ <--> Nomadnet specific to prevent page caching, may change if you like.

###################################################################################################################################
##    Welcome To: THE CHATROOM! - v2.00 by F. - The First Reticulum / Nomadnet IRC-STYLE Chat - Nomadnet & Meshchat compatible!  ##
##                                                                                                                               ##
##                                                                                                                               ##
##                          Full info on the official GitHub ReadMe: https://github.com/fr33n0w/thechatroom                      ##
##                                                                                                                               ##
##                            Come To Visit and Join The Original ChatRoom Nomadnet to see it in action:                         ##
##                                  NomadNet Link: d251bfd8e30540b5bd219bbbfcc3afc5:/page/index.mu                               ##
##                                                                                                                               ##
##                                                                                                                               ##
##  THIS NOMADNET PAGE PYTHON SCRIPT IS FREE AND OPEN SOURCE, PLEASE KEEP ORIGINAL LINKS INSIDE TO SUPPORT THE DEVELOPER'S WORK! ##
################################################### ENJOY YOUR NEW CHATROOM! ######################################################

######## IMPORT MODULES: ######## 
import os, sys, json, time, random, re, sqlite3

######## INITIALIZE LOG (LOCAL SYSTEM INFO MESSAGES) #####
log = []

######## SYS & FILE PATHS ######## 
DB_PATH = os.path.join(os.path.dirname(__file__), "chatusers.db")
EMO_DB = os.path.join(os.path.dirname(__file__), "emoticons.txt")

######## DB CREATION IF MISSING (on first start usually) ######
if not os.path.exists(DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            remote_identity TEXT,
            dest TEXT,
            display_name TEXT
        );
    """)
    conn.commit()
    conn.close()

######## DISPLAY LIMIT SETTINGS: ######## (Keeps UI fixed in the meshchat browser)
MAX_CHARS = 160  # Adjust as needed to split messages after N chars, 160 default for nomadnet
MAX_LINES = 28   # Max lines on screen, for Meshchat 
DISPLAY_LIMIT = 36 # Max lines on screen , for Nomadnet

######## MASTER SYSADMIN SETTINGS ######## (USE COMPLEX NICKNAMES FOR THE SYSADMINS!)
SYSADMIN = "setyouradminlognamehere" # SET YOUR MASTER ADMIN NICKNAME FOR CHAT ADMIN COMMANDS

######## UI Unicode Emojis: ######## 
user_icon = "\U0001F464" # "\U0001F464" # "\U0001F465" - "\U0001FAAA"
message_icon = "\U0001F4AC" 
msg2_icon = "\u2709\ufe0f"
send_icon = "\U0001F4E4"
totmsg_icon = "\U0001F4E9"
reload_icon = "\u21BB"
setup_icon = "\u2699\ufe0f"
cmd_icon = "\U0001F4BB" # \U0001F579
nickset_icon = "\U0001F504"
info_icon = "\u1F6C8"
stats_icon = "\u1F4DD"

######## Antispam filters: ######## (Add or remove what you want to allow or not)
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
    r"invest\s+in\s+(crypto|bitcoin|ethereum)",
    r"\bfree\s+(bitcoin|crypto|ethereum)\b",
    r"\bsell\s+(bitcoin|crypto|ethereum)\b",
    r"\bi\s+sell\s+(bitcoin|bitcoins|crypto|ethereum)\b",
    r"\bbuy\s+(bitcoin|crypto|ethereum)\b",
    r"\bget\s+(bitcoin|crypto|ethereum)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|crypto|ethereum)\b",
    r"\binvest\s+(in|into)\s+(bitcoin|crypto|ethereum)\b",
    r"\bbitcoin\s+(promo|deal|offer|discount)\b",
    r"\bcrypto\s+(promo|deal|offer|discount)\b",
    r"\bfree\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\b(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\s+for\s+you\b",
    r"\bsell\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bbuy\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bi\s+sell\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bget\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"\binvest\s+(in|into)\s+(bitcoin|bitcoins|coin|coins|crypto|tokens|ethereum)\b",
    r"(?:\W|^)(bitcoin|bitcoins|crypto|ethereum|tokens|coins)(?:\W|$)",
    r"\b(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\s+for\s+(free|you)\b",
    r"\bfree\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b",
    r"\bget\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b",
    r"\bmake\s+money\s+(with|from)\s+(bitcoin|bitcoins|crypto|ethereum|tokens|coins)\b",
    r"\b(sex|porn|xxx|nude|nudes|nsfw|onlyfans|camgirl|camgirls|adult\s+video|erotic|blowjob|anal|fetish|strip|escort|hardcore|incest|milf|hentai|boobs|naked|cumshot|threesome|gangbang|squirting|deepthroat)\b",
    r"\b(pornhub|xvideos|redtube|xnxx|xhamster|cam4|chaturbate|brazzers|bangbros|spankbang|fleshlight|adultfriendfinder|livejasmin|myfreecams|stripchat|sex.com)\b",
    r"\bwatch\s+(live\s+)?(sex|porn|camgirls|nudes)\b",
    r"\bfree\s+(porn|cams|nudes|xxx|sex\s+videos)\b",
    r"\bhot\s+(girls|milfs|teens|models)\s+(live|online|waiting)\b",
    r"\bclick\s+(here|link)\s+(for|to)\s+(sex|porn|nudes|xxx|cam)\b",
    r"\b(see|watch|join)\s+(my|our)?\s*(onlyfans|cam|sex\s+show)\b",
    r"\b(win(?:ner)?|guaranteed|prize|cash|credit|loan|investment|rich|easy\s+money|urgent)\b",
    r"\b(click\s+here|act\s+now|limited\s+time|exclusive\s+deal|verify\s+your\s+account|update\s+required|login\s+now|reset\s+password)\b",
    r"\b(discount|sale|offer|promo|buy\s+now|order\s+today|lowest\s+price|cheap|bargain|deal)\b",
    r"\b(bit\.ly|tinyurl\.com|goo\.gl|freegift|get-rich|fastcash|adult|xxx|cams|nudes)\b",
    r"\b(make\s+\$\d{2,}|earn\s+\$\d{2,}|work\s+from\s+home|no\s+experience\s+needed)\b",
    r"\b(earn|make)\s+(money|cash)\s+(from\s+home|online|fast|easily)\b",
    r"\b(work\s+from\s+home|no\s+experience\s+needed|easy\s+income|passive\s+income)\b",
    r"\b(start\s+earning|get\s+paid\s+daily|quick\s+cash|instant\s+money)\b",
    r"\b(earn|make)\s+(money|cash)\s+(from|at)\s+home\b",
    r"\b(work\s+(from|at)\s+home|easy\s+income|passive\s+income)\b",
    r"\b(start\s+earning|get\s+paid\s+(daily|instantly)|quick\s+cash|instant\s+money)\b",
    r"\b(work\s+(from|at)\s+home|easy\s+income|passive\s+income|get\s+paid\s+(daily|instantly)|quick\s+cash|instant\s+money)\b",
    r"\b(earn|make|get)\s+(money|cash|income)\s*(now|fast|quickly|easily)?\b",
    r"\b(passive\s+income|easy\s+money|no\s+experience|required|work\s+online|get\s+paid\s+(daily|instantly))\b",
    r"\b(earn|make|receive)\s+(some\s+)?(money|cash|income|profit|revenue)\b",

]

################### Nickname Auto-Color System ##################### (Change colors to your preferences)
colors = [ "B900", "B090", "B009", "B099", "B909", "B066", "B933", "B336", "B939", "B660", "B030", "B630", "B363", "B393", "B606", "B060", "B003", "B960", "B999", "B822", "B525", "B255", "B729", "B279", "B297", "B972", "B792", "B227", "B277", "B377", "B773", "B737", "B003", "B111", "B555", "B222", "B088", "B808", "B180" ]
def get_color(name):
    return colors[sum(ord(c) for c in name.lower()) % len(colors)]


#########  Recover input from Os Environment variables ######## 
def recover_input(key_suffix):
    for k, v in os.environ.items():
        if k.lower().endswith(key_suffix):
            return v.strip()
    return ""

raw_username     = recover_input("username")
message          = recover_input("message")
remote_identity  = recover_input("remote_identity")
nickname         = recover_input("field_username")
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

# Smart fallback for display name with logging
if nickname:
    display_name = nickname
elif dest:
    display_name = f"Guest_{dest_code}"
else:
    display_name = "Guest"

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

# Determine final display_name with logging
nickname_recovered_from_db = False

if nickname:
    display_name = nickname
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": f"`!` Nickname recovered from environment: {display_name} `!`"
    })
elif db_display_name:
    display_name = db_display_name
    nickname_recovered_from_db = True
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": f"`!` Nickname recovered from database: {display_name} `!`"
    })
elif dest:
    display_name = f"Guest_{dest[-4:]}"
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": f"`!` No nickname found. Using fingerprint: {display_name} `!`"
    })
else:
    display_name = "Guest"
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": "`!` No nickname or fingerprint found. Defaulting to Guest `!`"
    })

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

# Chat Topic functions
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
debug = []

try:
    with open(log_file, "r") as f:
        log = json.load(f)
        debug.append(f" Total {len(log)} messages")
except Exception as e:
    log = []
    debug.append(f"Failed to load log: {e}")

# USER COMMANDS LOGIC:
cmd = message.strip().lower()


##### ADMIN COMMANDS #####
if safe_username == SYSADMIN and cmd.startswith("/clear"):
    parts = cmd.split()

    if len(parts) == 1:
        # /clear ? remove last message
        if log:
            removed = log.pop()
            debug.append(f"Removed last message: <{removed['user']}> {removed['text']}")
        else:
            debug.append("No messages to clear.")

    elif len(parts) == 2 and parts[1].isdigit():
        # /clear N ? remove last N messages
        count = int(parts[1])
        removed_count = 0
        while log and removed_count < count:
            removed = log.pop()
            debug.append(f"Removed: <{removed['user']}> {removed['text']}")
            removed_count += 1
        debug.append(f"Cleared last {removed_count} messages.")

    elif len(parts) == 3 and parts[1] == "user":
        # /clear user NICKNAME ? remove all messages from that user
        target_user = parts[2]
        original_len = len(log)
        log[:] = [msg for msg in log if msg.get("user") != target_user]
        removed_count = original_len - len(log)
        debug.append(f"Cleared {removed_count} messages from user '{target_user}'.")

    else:
        debug.append("Invalid /clear syntax. Use /clear, /clear N, or /clear user NICKNAME.")

    # Save updated log
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2, ensure_ascii=False)
        debug.append("Log updated after clearing.")
    except Exception as e:
        debug.append(f"Clear command error: {e}")

elif safe_username == SYSADMIN and cmd == "/clearall":
    if log:
        log.clear()
        debug.append("All messages cleared by admin.")
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(log, f, indent=2, ensure_ascii=False)
            debug.append("Log successfully emptied.")
        except Exception as e:
            debug.append(f"ClearAll error: {e}")
    else:
        debug.append("Log already empty. Nothing to clear.")



########## CHAT USERS COMMANDS #########

#### STATS COMMAND ####
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
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": "`!` Stats Report: `!` "})
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": f"`!` Total messages: {total_messages} `!` "})
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": f"`!` Total users: {total_users} `!` "})
    
    # Combine top chatters in one line
    top_line = "`!` Top chatters: `!` " + " , ".join([f"`!` {user} ({count} msg) `!`" for user, count in top_users[:5]])
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": top_line})

############ /users COMMAND ##############
elif cmd == "/users":
    # Count messages per user
    from collections import Counter
    user_counts = Counter(msg["user"] for msg in log if msg["user"] != "System")

    # Sort by most active
    sorted_users = sorted(user_counts.items(), key=lambda x: -x[1])
    total_users = len(sorted_users)

    # Header line
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": f"`!` Active Users List and Stats, Total Users: ({total_users}) `! "
    })

    # Show in chunks of N with message counts
    for i in range(0, total_users, 7):
        chunk = ", ".join(f"`!` {user} `!({count}msg)" for user, count in sorted_users[i:i+7])
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": chunk
        })

############# /cmd COMMAND INFO LINES ############
elif cmd == "/cmd":
    help_lines = [
        f"`!{message_icon} THE CHATROOM!{message_icon}  \\  EXTENDED USER COMMANDS INFO:`!",
        f"`!GENERAL USE AND INFORMATIONAL COMMANDS:`!",
        f"`!/info`! :  Show The Chat Room! Informations, Usage and Disclaimer",
        f"`!/cmd`! : Show all the available user commands",
        f"`!/stats`! : Show chatroom statistics, including Top 5 Chatters",
        f"`!/users`! : List all chatroom users",
        f"`!/version`! : Show THE CHAT ROOM! script version, news and infos",

        f"`! {cmd_icon} INTERACTIVE CHAT COMMANDS`!",
        "`!/lastseen <username>`!`: Last seen user info and latest user message",
        "`!/topic`!` : Show or Change Room Topic, usage: '/topic' or '/topic Your New Topic Here' ",
        "`!/search <keyword(s)>`!` : Search for keywords in the full chatlog ",
        "`!/time`!` : Show current Chat Server Time (UTC)",
        "`!/ping`!` : Reply with PONG! if the chat system is up and working",
        "`!/meteo <cityname>`! : Get weather info for your city, example: /meteo Miami",
        "--------------------------------------",
        f"`! {cmd_icon} SOCIAL INTERACTIONS COMMANDS`!",
        "`!` /e`!` : Sends randomized emojis from the internal emoji list",
        "`!` /c <text message>`!` : Sends a colored chat message with randomized background and font colors",
        "`!` @nickname`!` : Sends a colored mention to highlight the mentioned user in a reply message",
        "`!` $e`!` : Sends a random emoticon using '$e', usable in every part of the message. ",
        "`!` $link`!` : Higlight your links, example: $link d251bfd8e30540b5bd219bbbfcc3afc5:/page/index.mu ",
        "`!` /welcome`! : Sends a welcome message. Usage: /welcome or /welcome <nickname>. ",
        f"`!` {cmd_icon} USER STATUS INTERACTIONS COMMANDS`!`",
        "`!` /hi, /bye, /brb, /lol, /exit, /quit, /away, /back, /notice `!`",
        "`!` Commands Usage Example:  /hi OR /hi Hello World! `! (Syntax is valid for all the above commands!)",
        "--------------------------------------",
        f"`!` {cmd_icon} ADMIN COMMANDS INFO: /admincmd (Only admins allowed to perform this command) `!`",
        "`!` --------- END OF COMMAND LIST: `[CLICK TO RELOAD THE PAGE`:/page/nomadnet.mu`username]` --------- `!",

    ]
    for line in help_lines:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": line
        })

######## /admincmd admin command ######## 
elif cmd == "/admincmd":
    if safe_username == SYSADMIN:
        admin_lines = [
            f"`! {cmd_icon} ADMIN COMMANDS INFO `!",
            "`! You have access to restricted administrative functions.`!",
            "`! /clear `! : Deletes last message from the chatroom and database permanently",
            "`! /clear N`! : Deletes last N messages from the chatroom and database permanently, example: /clear 3",
            "`! /clear user <nickname>`! : Delete all messages from a specified user permanently",
            "`! /clearall  `! : Permanently clear the whole chatroom log and database (Irreversible: use with caution!)",
            "`! /backup `! : Creates a full chat_log.json database backup in the same chatroom script folder",
            "--------------------------------------",
            "`! END OF ADMIN COMMANDS LIST `!"
        ]
        for line in admin_lines:
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": line
            })
    else:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": "`! ERROR: You do not have permission to use /admincmd. This command is restricted to SYSADMYN.`!"
        })

######### /backup admin command ########
elif cmd == "/backup":
    if safe_username == SYSADMIN:
        try:
            # Create timestamped backup filename in the same directory
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(os.path.dirname(__file__), f"chat_log_backup_{timestamp}.json")

            # Perform the backup
            import shutil
            shutil.copy(log_file, backup_file)

            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": f"`! Backup successful: {backup_file}`!"
            })
        except Exception as e:
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": f"`! ERROR: Backup failed. Reason: {str(e)}`!"
            })
    else:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": "`! ERROR: You do not have permission to use /backup - This command is restricted to SYSADMIN.`!"
        })


######## INFO COMMAND ######### (Change info with your preferences)
elif cmd == "/info":
    info_lines = [
        "`! The Chat Room v2.00 Info - Overview - Usage - Commands - Disclaimer - README! :) `!",
        "Welcome! This space is designed to connect people through an old school irc-styled interface.",
        "No registration required, set your nickname and you are ready to message with other users.",
        "Nicknames are randomly colorized and there is persistent color for every nickname.",
        "No privacy compromission: use any nick you want. Nothing is recorded or associated to your rns identity.",
        "This runs on a Nomadnet, so it will be visible internationally. Respect all the user languages in chat.",
        "This chat is based on micron, sql3 db and python components.",
        "You can send irc-style messages and use various commands to explore the chatroom.",
        "`!` Command Reference `!`",
        "Just Some Examples:",
        "/users : show active users and message counts",
        "/lastseen <username> : check a user's recent activity",
        "/topic : show or change the room topic",
        "/stats : show chat stats including top chatters",
        "`!` Use /cmd to view the full list of available commands. `!`",
        "`!` Technical Notes `!`",
        "Due to micron limitations, the chatroom does not refresh automatically.",
        "To see new incoming messages, reload the page using the provided link buttons.",
        "Especially on Nomadnet: Reload using the provided link in the bottom bar to avoid duplicate messages!",
        "Refreshing the page using meshchat browser function will remove nickname persistance, so use our Reload button",
        "To have a nickname persistency, use the Meshchat v2.+ Fingerprint Button to save and recall (lxmf binding).",
        "The main chatroom shows the last ~30 messages; use the button at the bottom to view the full chat log.",
        "`!` DISCLAIMER `!`",
        "This chatroom is a space for connection, collaboration, and respectful interaction.",
        "Rude, offensive, or inappropriate behavior is not tolerated. Messages may be deleted.",
        "Suspension or message deletion can occur without prior warning in serious or repeated cases.",
        "`!` BEFORE FREE SPECH, COMES RESPECT! - WELCOME TO >>THE CHAT ROOM!<< `!`"           
    ]

    for line in info_lines:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": line
        })

############ TIME COMMAND ###############
elif cmd == "/time":
    from datetime import datetime
    server_time = datetime.utcnow().strftime("%A, %B %d, %Y at %H:%M:%S UTC")
    time_text = f"Current server time: {server_time}"
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": time_text})

########## VERSION COMMAND #########  EDIT FOR YOUR LOCAL SETTINGS!
elif cmd == "/version":
    version_messages = [
        "The Chat Room v2.00 / Powered by Reticulum NomadNet / IRC Style / Nomadnet & Meshchat Compatible / Made by F",
        "This chat is running on a VPS server, powered by RNS v1.0.0 and Nomadnet v.0.8.0.",
        "Latest Implementations in v1.3b: AntiSpam Filter and Nickname persistency (Thanks To: Thomas!!)",
        "Latest Implementations in v1.4b: Improved UI with Message splitting on long messages",
        "Latest Implementations in v1.44b: Improved UI, resolved few UI bugs, added Menu Bar on the bottom, added /search command, added 'Read Last 100 Messages', started implementing user settings (for future user preferences: custom nickname colors, multiple chat themes and more...coming soon!)",
        "Latest Implementations in v1.45b:",
        "Added Social Interactions Commands, for full command list: /cmd",
        "Improved UI and readability, fixed dysplay limit function!",
        "Latest Implementations in v1.45a:",
        "Alpha Stable Version Release Ready - Improved display limit function",
        "Added SYSADMIN commands (type /admincmd for help, only allowed for SYSADMIN) ",
        "Improved AntiSpam Filters, Better UI Timestamp, Added /meteo command",
        "The ChatRoom v2.00 improvements:",
        "Code Cleaning , Nomadnet and Meshchat supported, new intro page, timestamp mod, overall script and page improvements",
        "`! Get The ChatRoom at: https://github.com/fr33n0w/thechatroom `!"
    ]

    for msg in version_messages:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": msg
        })


######## LASTSEEN COMMAND ########
elif cmd.startswith("/lastseen "):
    target_user = cmd[10:].strip()
    last = next((msg for msg in reversed(log) if msg["user"] == target_user), None)
    seen_text = f"Last seen {target_user} at {last['time']}: {last['text']}" if last else f"No record of user '{target_user}'."
    log.append({"time": time.strftime("[%a,%H:%M]"), "user": "System", "text": seen_text})

######## TOPIC COMMAND ######## 
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
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": f"Topic set by {safe_username} on {timestamp}: {trimmed_topic} , Reload The Page!"
            })
        except Exception as e:
            debug.append(f"Topic update error: {e}")
    else:
        debug.append("No topic text provided.")

elif cmd == "/topic":
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": f"Current Topic: {topic_text} (set by {topic_author} on {topic_data.get('time')})"
    })

######## SEARCH COMMAND ######## 
elif cmd.startswith("/search"):
    search_input = message[8:].strip().lower()

    if not search_input:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": "`!` Error! Command Usage: /search <keywords> - Please provide one or more keywords! `!`"
        })
    else:
        keywords = search_input.split()
        matches = []

        for msg in log:
            if msg.get("user") == "System":
                continue
            text = msg.get("text", "").lower()
            if all(kw in text for kw in keywords):
                matches.append(msg)

        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Search Results for: '{search_input}' - {len(matches)} match(es) found. `!`"
        })

        for match in matches[:10]:
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": f"[{match.get('time', '??')}] <{match.get('user', '??')}> {match.get('text', '')}"
            })

        if len(matches) > 10:
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": "`!` Showing first 10 results. Refine your search for more specific matches. `!`"
            })

######## PING COMMAND ######## 
elif cmd == "/ping":
    log.append({
        "time": time.strftime("[%a,%H:%M]"),
        "user": "System",
        "text": "PONG! (System is up and working!)"
    })

#########  /e RANDOM EMOJIS COMMAND ######## 
elif cmd == "/e":
    try:
        with open(EMO_DB, "r", encoding="utf-8") as f:
            emojis = [line.strip() for line in f if line.strip()]
        
        if emojis and safe_username:
            import random
            chosen = random.choice(emojis)

            # Treat emoji as a normal message
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": safe_username,
                "text": chosen
            })

            try:
                with open(log_file, "w") as f:
                    json.dump(log, f)
                debug.append(f" Emoji by '{safe_username}' sent: {chosen}")
            except Exception as e:
                debug.append(f" Emoji send error: {e}")
        else:
            log.append({
                "time": time.strftime("[%a,%H:%M]"),
                "user": "System",
                "text": "`!` Emoji list is empty or username missing. `!`"
            })
            debug.append(" Emoji command skipped: missing emoji or username.")
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error loading emojis: {e} `!`"
        })
        debug.append(f" Emoji command error: {e}")

######## ##### COLOR /c COMMAND ######## ######
elif cmd.startswith("/c "):
    user_message = message[3:].strip().replace("`", "")  # Remove backticks to avoid formatting issues

    if user_message and safe_username:
        import random, json

        def hex_brightness(hex_code):
            r = int(hex_code[0], 16)
            g = int(hex_code[1], 16)
            b = int(hex_code[2], 16)
            return (r + g + b) / 3

        # Generate random hex color for background
        bg_raw = ''.join(random.choices("0123456789ABCDEF", k=3))
        bg_color = f"B{bg_raw}"

        # Calculate brightness
        brightness = hex_brightness(bg_raw)
        font_color = "F000" if brightness > 7.5 else "FFF"

        # Split message into chunks of 80 characters
        def split_and_colorize(text, chunk_size=80):
            chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
            return '\n'.join([f"`{bg_color}`{font_color}` {chunk} `b`f" for chunk in chunks])

        colorful_text = split_and_colorize(user_message)

        # Create log entry
        entry = {
            "time": time.strftime("[%a,%H:%M]"),
            "user": safe_username,
            "text": colorful_text
        }

        log.append(entry)

        # Write to JSON file
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(log, f)
            debug.append(f"Test: Colored Message succesfully sent! by '{safe_username}'")
        except Exception as e:
            debug.append(f"Error sending colored message: {e}")
    else:
        debug.append("Error: Color command skipped due to missing message or username.")

###### /HI COMMAND #######
elif cmd.startswith("/hi"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} has joined The Chat Room!"
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /hi command: {e} `!`"
        })

###### /BYE COMMAND #######
elif cmd.startswith("/bye"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} is leaving The Chat Room!"
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /bye command: {e} `!`"
        })

###### /quit COMMAND #######
elif cmd.startswith("/quit"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} has quit The Chat Room!"
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /quit command: {e} `!`"
        })

###### /exit COMMAND #######
elif cmd.startswith("/exit"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} has left The Chat Room!"
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /exit command: {e} `!`"
        })

###### /BRB COMMAND #######
elif cmd.startswith("/brb"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} has left The Chat Room! I'LL BE RIGHT BACK! BRB!"
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /brb command: {e} `!`"
        })

###### /lol COMMAND #######
elif cmd.startswith("/lol"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} is Laughing Out Loud! LOL! :D "
        if user_message:
            full_text = f" `!{base_text} Message: {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /lol command: {e} `!`"
        })

###### /away COMMAND #######
elif cmd.startswith("/away"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} is away."
        if user_message:
            full_text = f" `!{base_text} (Status: {user_message}) `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /away command: {e} `!`"
        })

###### /back COMMAND #######
elif cmd.startswith("/back"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} is back! "
        if user_message:
            full_text = f" `!{base_text} {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /back command: {e} `!`"
        })


###### /welcome COMMAND #######
elif cmd.startswith("/welcome"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"{colored_nickname} Welcomes "
        if user_message:
            full_text = f" `!{base_text} {user_message} `!"
        else:
            full_text = f" `!{base_text} everyone! `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /welcome command: {e} `!`"
        })

###### /notice COMMAND #######
elif cmd.startswith("/notice"):
    try:
        parts = cmd.split(" ", 1)
        user_message = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")
        # Get color code for nickname
        nickname_color = get_color(safe_username)
        # Format nickname using your markup style
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        # Build message
        base_text = f"NOTICE FROM {colored_nickname}:"
        if user_message:
            full_text = f" `!{base_text}  {user_message} `!"
        else:
            full_text = f" `!{base_text} `!"
        log.append({
            "time": timestamp,
            "user": "System",
            "text": full_text
        })
        with open(log_file, "w") as f:
            json.dump(log, f)
    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"`!` Error processing /notice command: {e} `!`"
        })

####### METEO COMMAND #######
elif cmd.startswith("/meteo"):
    try:
        from geopy.geocoders import Nominatim
        import requests

        # Extract city name
        parts = cmd.split(" ", 1)
        city_name = parts[1].strip() if len(parts) > 1 else ""
        timestamp = time.strftime("[%a,%H:%M]")

        if not city_name:
            raise ValueError("No city name provided. Example: /meteo New York")

        # Geolocation
        geolocator = Nominatim(user_agent="weather_bot")
        location = geolocator.geocode(city_name)
        if not location:
            raise ValueError(f"Could not find location for '{city_name}'.")

        lat, lon = location.latitude, location.longitude

        # Open-Meteo API call
        weather_url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true"
        response = requests.get(weather_url)
        data = response.json()

        if "current_weather" not in data:
            raise ValueError("Weather data not available.")

        temp = data["current_weather"]["temperature"]
        code = data["current_weather"]["weathercode"]

        # Weather code mapping (no emojis)
        weather_codes = {
            0: "Clear sky",
            1: "Mainly clear",
            2: "Partly cloudy",
            3: "Overcast",
            45: "Fog",
            48: "Depositing rime fog",
            51: "Light drizzle",
            53: "Moderate drizzle",
            55: "Dense drizzle",
            56: "Light freezing drizzle",
            57: "Dense freezing drizzle",
            61: "Slight rain",
            63: "Moderate rain",
            65: "Heavy rain",
            66: "Light freezing rain",
            67: "Heavy freezing rain",
            71: "Slight snow fall",
            73: "Moderate snow fall",
            75: "Heavy snow fall",
            77: "Snow grains",
            80: "Slight rain showers",
            81: "Moderate rain showers",
            82: "Violent rain showers",
            85: "Slight snow showers",
            86: "Heavy snow showers",
            95: "Thunderstorm",
            96: "Thunderstorm with slight hail",
            99: "Thunderstorm with heavy hail"
        }

        description = weather_codes.get(code, "Unknown weather")

        # Format nickname
        nickname_color = get_color(safe_username)
        colored_nickname = f"`{nickname_color}{safe_username}`b"
        weather_text = f"Weather in {city_name}: {temp}C, {description}"

        full_text = f"Meteo Request from {colored_nickname}: {weather_text} "
        log.append({
            "time": timestamp,
            "user": "Meteo",
            "text": full_text
        })

        with open(log_file, "w") as f:
            json.dump(log, f)

    except Exception as e:
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"Error processing /meteo command: {e} "
        })


##################### END OF COMMANDS, CONTINUE SCRIPT ##############################

elif raw_username and message and message.lower() != "null":
    sanitized_message = message.replace("`", "").replace("[", "")  # remove backticks and [ to prevent formatting issues

######### Spam detection logic ######## 
# banned_words = ["buy now", "free money", "click here", "subscribe", "win big", "limited offer", "act now"] , 
# edit your spam filters on top of the script

    trigger_word = next((pattern for pattern in spam_patterns if re.search(pattern, sanitized_message.lower())), None)
    is_spam = trigger_word is not None

    if is_spam:
        # Don't write to JSON, just log the system message
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
            "user": "System",
            "text": f"Spam Detected! Message Blocked! Triggered by: '{trigger_word}'"
        })
        debug.append(f" Spam blocked from '{safe_username}'")
    else:
        # Normal message flow
        log.append({
            "time": time.strftime("[%a,%H:%M]"),
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
    debug.append(" Page Reloaded. Idle. Void Message. Waiting for user interactions. For extended commands info digit: /help")




#########  Helper function to split long messages using MAX CHARS ######## 
def split_message(text, max_chars):
    words = text.split()
    lines = []
    current_line = ""
    for word in words:
        if len(current_line) + len(word) + 1 <= max_chars:
            current_line += (" " if current_line else "") + word
        else:
            lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)
    return lines

#########  dynamic ui displayed messages adaptation ######## 
def calculate_effective_limit(log, max_lines, max_chars):
    total_lines = 0
    effective_limit = 0

    for msg in reversed(log):
        lines = len(split_message(msg["text"], max_chars))
        if total_lines + lines > max_lines:
            break
        total_lines += lines
        effective_limit += 1

    return max(effective_limit, 1), total_lines

effective_limit, total_lines = calculate_effective_limit(log, MAX_LINES, MAX_CHARS)


########## UTC server time to local time dynamic conversion ########## 
from datetime import datetime

def convert_log_time_to_local(log_time_str):
    # Parse log time - handle both [HH:MM] and [Day,HH:MM] formats
    log_time_str = log_time_str.strip("[]")
    
    # Check if it has day of week prefix (with or without space after comma)
    if "," in log_time_str:
        # New timestamp format: [Tue,14:23] or [Tue, 14:23]
        parts = log_time_str.split(",")
        day_part = parts[0].strip()
        time_part = parts[1].strip()
    else:
        # Old format: [14:23]
        time_part = log_time_str
        day_part = None
    
    # Get today's date
    today = datetime.utcnow().date()
    
    # Parse as UTC
    utc_dt = datetime.strptime(f"{today} {time_part}", "%Y-%m-%d %H:%M")
    
    # Get system's local timezone-aware datetime
    local_now = datetime.now().astimezone()
    
    # Replace tzinfo of utc_dt with UTC, then convert to local timezone
    utc_dt = utc_dt.replace(tzinfo=local_now.tzinfo)
    local_dt = utc_dt.astimezone()
    
    return local_dt.strftime("%a,%H:%M")

#########  mention users def logic on @user message ######## 
def highlight_mentions_in_line(line, known_users):
    def replacer(match):
        nickname = match.group(1)
        if nickname in known_users:
            color = get_color(nickname)
            return f"`!@`{color}{nickname}`b`!"
        else:
            return f"@{nickname}"  # Leave uncolored
    return re.sub(r"@(\w+)", replacer, line)

######## $E FOR EMOTICONS ######## 
with open(EMO_DB, "r", encoding="utf-8") as f:
    EMOTICONS = []
    for line in f:
        EMOTICONS.extend(line.strip().split())
# $e catching for emoticons in messages
def substitute_emoticons_in_line(line):
    return re.sub(r"\$e", lambda _: random.choice(EMOTICONS), line)

######## LINK MENTIONS ######
def format_links_in_line(line):
    def replacer(match):
        link = match.group(1)
        return f"`*`_`Fb9f`[{link}]`_`*`f` "
    
    # Match `$link` followed by a space and then the actual link
    return re.sub(r"\$link\s+([^\s]+)", replacer, line)

############################## Output UI template: ######################################

# Build set of known usernames
known_users = {msg["user"] for msg in log}


# sanitize and read name from display_name os env
safe_display_name = display_name.replace("`", "'")


# RENDER UI:

# Simple template for NomadNet compatibility
template = "---\n"
template += f">`!{message_icon}  THE CHAT ROOM! {message_icon}  `F007` Powered by Reticulum NomadNet - IRC Style - Free Global Chat Room - Optimized for NomadNet - v2.00 `f`!\n"
template += "---\n"
template += f"`c`B000`Ff2e`!####### Room Topic: {topic_text} `! (Set by: {topic_author}, {topic_data.get('time')}) `! `!`f`b`a\n"
template += "---\n"

# Simple chat display with all substitutions
for msg in log[-DISPLAY_LIMIT:]:
    message_lines = split_message(msg["text"], MAX_CHARS)
    color = get_color(msg["user"])
    
    for i, line in enumerate(message_lines):
        # Apply substitutions for non-System messages
        if msg["user"] != "System":
            line = substitute_emoticons_in_line(line)  # Replace $e
            line = highlight_mentions_in_line(line, known_users)  # Highlight @mentions
            line = format_links_in_line(line)  # Format $link
        
        if i == 0:
            # First line with timestamp and user
            template += f"\\{msg['time']} `{color}`!<{msg['user']}>`!`f`b {line}\n"
        else:
            # Continuation lines
            template += f"\\{msg['time']} `{color}`!<{msg['user']}>`!`f`b {line}\n"


template += "---\n"
template += f"`B317 {user_icon} Nickname: `Baac`F000`<20|username`{safe_display_name}>`b`f `B317`_`[{nickset_icon} (Set/Update)`:/page/nomadnet.mu`username]`_`  {message_icon} Message: `Baac`F000`<87|message`>`b`f `B317`_`[{send_icon} Send Message`:/page/nomadnet.mu`username|message]`_` - `_`[Reload Page`:/page/nomadnet.mu`username]`_`\n"
template += "---\n"
template += f"`B216`Fddd` {cmd_icon} User Commands: /info, /stats, /users, /version, /lastseen, /topic, /search, /time, /ping, /meteo, /hi, /bye, /brb, /lol, /quit, /away,     ...For Full Command List, digit: /cmd `b`f\n"
template += f"`B317`Feee` `!` {message_icon}  Total Messages: ({len(log)}) | {message_icon}  On Screen Messages: ({total_lines}) | {totmsg_icon}  `[Read Last 100`:/page/last100.mu]`  |  {totmsg_icon}  `[Read Full Chat Log (Slow)`:/page/fullchat.mu]`!  | `!`[{setup_icon}  User Settings (This function is not available yet, coming soon)`:/page/nomadnet.mu`username]`!`b`f"
template += "\n---\n"
template += "---"
print(template)