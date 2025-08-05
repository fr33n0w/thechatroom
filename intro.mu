#!/usr/bin/env python3
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Scan for JSON files in that directory
json_files = [f for f in os.listdir(script_dir) if f.endswith('.json')]
channel_names = [os.path.splitext(f)[0] for f in json_files]


intro = "`F533`B222-\n`b`f\n\n"
intro += "`c"       
intro += "`F533`B222-`F533`Bfff `!` WELCOME TO: << THE CHAT ROOM! >> `!`b`f `F533`B222-`b`f\n\n"

intro += "`F533`B222-`Fa55`B333 Powered by Reticulum / NomadNet - IRC Style - Optimized for Meshchat - v1.2b `b`f `F533`B222-`b`f\n"
intro += "\n"
intro += "`F533`B222-\n`b`f\n\n\n\n"
intro += "`Fe0f `!` #CHANNEL LIST: `!`f\n"
intro += "`F533`B222-\n`b`f\n\n"

for name in channel_names:
    intro += f"`Ffaa`!` {name} `!`f\n"


print(intro)
