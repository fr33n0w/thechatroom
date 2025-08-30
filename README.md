# 💬 **The Chat Room!** 💬

An IRC-style chat room built for **Reticulum NomadNet**, optimized for **MeshChat v2.1+**. Made By F.

---

## 🖼️ The Chat Room UI

Screenshot from MeshChat interface:

<img width="1316" height="851" alt="the chat room" src="https://github.com/user-attachments/assets/371dbcc7-16df-4420-bee8-ec546e3ade3d" />

---

## 🚀 Live Demo

Experience the chatroom in action via the official NomadNet page:

**NomadNet Page Link (MeshChat v2.1+ Optimized):**  `d251bfd8e30540b5bd219bbbfcc3afc5:/page/index.mu`

---

# Informations

Welcome to **THE CHATROOM** – v1.45a by F.  
The first Reticulum/Nomadnet IRC-style chatroom, optimized for Meshchat v2.x+.

Born on v1 (beta) the 10 of August 2025. Enjoy!

**Note:** 
This chatroom page was developed using MeshChat Browser so it's optimized for MeshChat v2.1+ only, could be unreadable on Nomadnet browser.

A simpler Nomadnet version is coming soon, work in progress, stay tuned!

The script page is considered in alpha stage of development, stay tuned for new changes and updates!
---

## 📘 Project Overview

This is a Python-based Nomadnet page script that creates a ready-to-run IRC-style chatroom.  
Just copy all files from this GitHub release into your `./nomadnetwork/storage/pages/` folder,  
make `index.mu` executable with `chmod +x`, and launch your Nomadnet node.

Detailed installation info below.

- 🌍 Decentralized mesh-based communication based on NomadNetwork
- 🧑‍💻 No registration required—just choose a nickname and start chatting
- 🎨 Nicknames are randomly colorized and persist across sessions (user settings personalization is coming soon!)
- 🔒 Nickname to LXMF address binding, using the Fingerprint in Meshchat v2+ to save and recover the nickname across sessions
  (THANKS TO: **THOMAS**)
- 🛠️ Built with Python and Micron components, JSON and SQL DBs for chat, topic and nickname persistency
- 🌐 Official chat script is Hosted on a VPS for stable uptime

Live Demo:  `d251bfd8e30540b5bd219bbbfcc3afc5:/page/index.mu`  

Official GitHub: [https://github.com/fr33n0w/thechatroom](https://github.com/fr33n0w/thechatroom)

---

---
# 🆘 Help Page

Welcome to the Help section! This guide outlines all the modules required to run this project, 

along with setup instructions to get you started smoothly.

## 🧰 Requirements

This project uses a combination of Python’s built-in modules and third-party libraries.

### ✅ Built-in Modules (No installation required)

These come bundled with Python and require no additional setup:

| Module              | Purpose                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `os`                | Interacts with the operating system (e.g., file paths, environment vars)|
| `sys`               | Accesses system-specific parameters and functions                       |
| `json`              | Parses and manipulates JSON data                                        |
| `time`              | Handles time-based operations (e.g., delays, timestamps)                |
| `random`            | Generates random values and selections                                  |
| `re`                | Performs pattern matching with regular expressions                      |
| `shutil`            | Performs high-level file operations (e.g., copying, moving files)       |
| `collections`       | Provides specialized data structures like `Counter`                     |
| `datetime`          | Manages date and time objects                                           |

### 🌐 Third-Party Libraries (Install via pip)

These must be installed manually:

| Package     | Purpose                                                                 |
|-------------|-------------------------------------------------------------------------|
| `pytz`      | Timezone definitions and conversions                                    |
| `requests`  | Simplified HTTP requests and API calls (needed for /meteo command only) |
| `geopy`     | Geolocation services (e.g., address lookup via Nominatim, as above)     |
| `sqlite3`   | Manages local SQLite database storage for Nickname to LXMF binding      |

To install them, run:

```bash
pip install pytz requests geopy sqlite3
```

and of course, you need to install and configure NomadNet to host the page:

```bash
pip install nomadnet
```

Tested and 100% working also with rns_server_pages by SebastianObi:
https://github.com/SebastianObi/RNS-Tools/tree/main/rns_server_page

---

## ⚙️ Installation

Ready to deploy **THE CHATROOM** on your NomadNet node? Follow these steps to get it running in minutes:

---

### 📁 1. Download the Files

Clone the repository or download the ZIP:

```bash
git clone https://github.com/fr33n0w/thechatroom.git
```

### 📂 2. Copy Files to NomadNet Pages Directory

```bash
cp -r thechatroom/* ~/.nomadnetwork/storage/pages/

```

### 🔓 3. Make index.mu and other python pages Executable

```bash
chmod +x ~/.nomadnetwork/storage/pages/index.mu
chmod +x ~/.nomadnetwork/storage/pages/fullchat.mu
chmod +x ~/.nomadnetwork/storage/pages/last100.mu
```
Also make sure your user has read and write permission for the json and db files!

### 🚀 4. Launch NomadNet
Install and configure Nomadnet (or other nomadnet hosting page servers), after configuration:
```bash
nomadnet
```

# DONE!

Note: TheChatRoom has been created and runt on root user machines, probably you need to be root to run it, let me know if you encounter some difficulties!

LXMF Contact: 0d051f3b6f844380c3e0c5d14e37fac8
---

---

## ⚙️ Technical Notes

Here are some important details about how **THE CHATROOM** works and what to expect:

- 🔄 The chatroom does **not auto-refresh** due to Micron limitations  
  → Use the **Reload buttons** that you find in the bottom menubar to view new messages  
- 🧠 Nicknames can be stored using MeshChat’s **Fingerprint binding**
  - Usage: press fingerprint button, set a nickname and reload the page. Nick is saved. 
  → This allows nickname persistence across sessions (thanks to Thomas!)
  - To recover the nickname on lost session cache, press fingerprint again and it will reappear automatically
- 📜 The main chat view shows the **last 30 messages**  to fit MeshChat browser windows, you cn adjust the limit in the script
  → Full logs are available via the **View Logs** button on the bottom menù
- 🧪 The `/meteo` command uses external APIs  
  → Requires `requests` and `geopy` to be installed  
- 🧱 Built with Python and Micron components  
  → Compatible with MeshChat v2.1+ only, pure NomadNet version is coming soon!  
- 🧪 More Features will come soon! Stay Tuned!

---

---

## 💬 Commands Reference

Here’s the full list of available commands in **THE CHATROOM**, grouped by category for easy reference:

---

### 📘 General Info & Utility Commands

| Command           | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `/info`           | Show chatroom information, usage, and disclaimer                            |
| `/cmd`            | Display all available user commands                                          |
| `/stats`          | Show chatroom statistics, including Top 5 Chatters                          |
| `/users`          | List all active chatroom users                                              |
| `/version`        | Show script version, latest updates, and news                               |

---

### 🧠 Interactive Chat Commands

| Command                     | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| `/lastseen <nickname>`      | Show last seen info and latest message from a user                         |
| `/topic` or `/topic <text>` | View or change the current room topic                                      |
| `/search <keyword(s)>`      | Search for keywords in the full chat log                                   |
| `/time`                     | Show current server time (UTC) and your local time                         |
| `/ping`                     | Reply with PONG! to confirm chat system is active                          |
| `/meteo <city>`             | Get weather info for a city (requires internet + API)                      |

---

### 🎭 Social Interaction Commands

| Command                     | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| `/e`                        | Send randomized emojis from the internal emoji list                         |
| `/c <message>`              | Send a colored message with randomized background and font colors           |
| `@nickname`                 | Mention a user with a colored highlight                                     |
| `$e`                        | Insert a random emoticon anywhere in your message                           |
| `/welcome` or `/welcome <nickname>` | Send a welcome message to the room or a specific user               |

---

### 👤 User Status Commands

| Command                     | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| `/hi`, `/bye`, `/brb`, `/lol`, `/exit`, `/quit`, `/away`, `/back`, `/notice` | Send status updates or reactions |
| Example                     | `/hi Hello World!` — syntax works for all status commands                   |

---

### 🔒 Admin Commands (Restricted Access)

> Only available to system administrators via `/admincmd`

| Command                          | Description                                                             |
|----------------------------------|-------------------------------------------------------------------------|
| `/clear`                         | Delete the last message permanently                                     |
| `/clear N`                       | Delete the last N messages, e.g. `/clear 3`                             |
| `/clear user <nickname>`         | Delete all messages from a specific user                                |
| `/clearall`                      | Clear the entire chat log and database (irreversible)                   |
| `/backup`                        | Create a full `chat_log.json` backup in the script folder               |

---

> ⚠️ Some commands require internet access or third-party libraries (`requests`, `geopy`).  
> 🔐 Admin commands are protected and only executable by authorized users. (Edit SYSADMIN nickname in the script!!)

---

## Other Features:

### AntiSpam

The ChatRoom! includes already a good list of antispam filters, based on single words or combined phrases. Add your own or remove the unwanted blocked words to make it less strict in spam_patterns lines section of the script. 

## Fixed UI Windows
The UI is fixed in place with DISPLAY_LIMIT var, limited to 28 messages to fit the MeshChat 2.0+ Nomadnet Browser window. 

## NickName Color System
Automatically color the user nickname for better readability, keeps it persistant for any message or command, same nick, same color, you can edit the default colors in the script.

## Nickname & LXMF fingerprint binding (Thanks to Thomas!)
Pressing the Fingerprint button on meshchat v2.1+ , you send your lxmf to the chat and the script will automatically bind the nickname and the lxmf address like a sort of autologin. on rejoining the chat, nickname will be automatically recovered. if the meshchat os variables are missing (in case of reboot for example), just press fingerprint again and based on your lxmf, your nickname will reappear again automatically. Nickname and corresponding LXMF address is saved in a sql db to be recovered.

## Long messages split function
On longer messages, they will automatically be split in multiple lines to keep persistant ui layout and format.

## Statistics and users commands
Show chat statistics, top chatters, total sent message per user, total users in chat (commands: /stats or /users)


---

## Next Work In Progress Features:

### Personalized User Settings
(eg. set your nickname color preferences, possibility to click nickname to share your lxmf address for private chat, remove your nick and lxmf binding, chat theme selection, ecc.)

### More Administration Commands
(eg. Add or Remove multiple Administrators)
