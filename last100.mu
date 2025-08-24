#!/usr/bin/env python3
import os, json

# ?? Message log
log_file = os.path.join(os.path.dirname(__file__), "chat_log.json")
debug = []
try:
    with open(log_file, "r") as f:
        log = json.load(f)
        debug.append(f"Total {len(log)} messages loaded.")
except Exception as e:
    log = []
    debug.append(f"Failed to load log: {e}")

# Show only the last 100 messages
log = log[-100:] if len(log) > 100 else log
debug.append(f"Displaying last {len(log)} messages.")

# ?? Colors
colors = [
    "B900", "B090", "B009", "B099", "B909", "B066", "B933", "B336", "B939",
    "B660", "B030", "B630", "B363", "B393", "B606", "B060", "B003", "B960", "B999",
    "B822", "B525", "B255", "B729", "B279", "B297", "B972", "B792", "B227", "B277",
    "B377", "B773", "B737", "B003", "B111", "B555", "B222", "B088", "B808", "B180"
]
def get_color(name):
    return colors[sum(ord(c) for c in name.lower()) % len(colors)]

# ?? Build Partial Log UI
template = "> ?? RECENT CHAT LOG - Showing last 100 messages - Reload to update - Press Back to return to The Chat Room!\n\n"
for msg in log:
    color = get_color(msg["user"])
    template += f"[{msg['time']} `{color}` `!` `*` <{msg['user']}>`b `!` `*` {msg['text']}\n"

template += f"\n>`B777`Faaa` Displayed Messages: {len(log)}`b`F"
for line in debug:
    template += f"\n>`B888` {line}`b"

print(template)
