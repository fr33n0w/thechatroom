#!/usr/bin/env python3

import os
import sqlite3
import datetime

DB_PATH = 'users.db'
PAGE_PATH = '/intro.mu'
TITLE = ' `!` `B112`>>> THE CHAT ROOM! <<< `!`b \n `Baaa`F009` Powered by Reticulum / NomadNet - IRC Style - Free Global Chat Room - Optimized for Meshchat - v1.2b `f `!`b '

def header():
    print('#!c=0')
    print(f'''
-
-
`c{TITLE}
-
`a
-
''')

def print_env_cache():
    excluded_keys = {'PATH', 'link_id', 'LC_CTYPE'}
    print('- Environment Cache (excluding PATH, link_id, LC_CTYPE) -')
    for key, value in os.environ.items():
        if key not in excluded_keys:
            print(f'{key}: {value}')
    print('-' * 40)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            identity TEXT PRIMARY KEY,
            nickname TEXT,
            lxmf_address TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    return conn

def get_user(conn, identity):
    cursor = conn.cursor()
    cursor.execute('SELECT nickname, lxmf_address FROM users WHERE identity = ?', (identity,))
    return cursor.fetchone()

def save_user(conn, identity, nickname, lxmf_address):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (identity, nickname, lxmf_address, timestamp)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(identity) DO UPDATE SET
            nickname=excluded.nickname,
            lxmf_address=excluded.lxmf_address,
            timestamp=excluded.timestamp
    ''', (identity, nickname, lxmf_address, get_time()))
    conn.commit()

# Start page
header()
print_env_cache()
conn = init_db()

remote_identity = os.environ.get('remote_identity')
nickname = os.environ.get('field_nickname')
dest = os.environ.get('dest')  # LXMF address
lxmf_share = os.environ.get('lxmf_share')
change_nick_mode = os.environ.get('change_nick')

if remote_identity:
    hash_code = remote_identity[-4:]
    user_data = get_user(conn, remote_identity)

    if user_data and not nickname:
        nickname = user_data[0]

    print(f'> Identity: {remote_identity} ({hash_code})')
    if dest:
        print(f'> LXMF Address: {dest}')

    if nickname and not change_nick_mode:
        print(f'''

>Welcome back, `B111`Faaa` {nickname}`b!

Set a new nickname: `B444` <{nickname}>`b! `!`[<Set & Save>`:/page/index.mu`]`!
Your Identity is: {remote_identity}
Your LXMF Address: {dest}


`!`[<Join Chatroom>`:/page/index.mu`]`!  `!`[<Nickname & Settings>`:/page/settings.mu`]`!
''')
        if lxmf_share == '1':
            save_user(conn, remote_identity, nickname, dest)
        else:
            save_user(conn, remote_identity, nickname, None)
    else:
        print('Nickname: `B444`<nickname`>`b')
        print(f'''
`!`[<Set>`:{PAGE_PATH}`nickname|lxmf_share]
`B444`<?|lxmf_share|1`>`b Share LXMF address
''')
else:
    print('> Attention please!')
    print('Ensure you identify yourself to the node by clicking on the fingerprint button above')
