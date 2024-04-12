#!/usr/bin/env python3
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import os
import sys
import json
import requests

chat_id = os.environ.get("TBOT_CHAT")             # chat id. env TBOT_CHAT must be set!
token = os.environ.get("TBOT_TOKEN")              # bot token. env TBOT_TOKEN must be set!
parse_mode = os.environ.get("TBOT_FORMAT", '')    # HTML, MarkdownV2 or empty

for key in ["TBOT_CHAT", "TBOT_TOKEN"]:
    if not os.environ.get(key):
        print(f"Please set environmental variable \"{key}\"")
        sys.exit(1)


def sendMessage(msg, passthrough=True):

    if passthrough:
        print(msg)

    if len(msg) == 0:
        return '{"ok":true}'

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    if len(msg) > 4096:
        msg = "Message output is too long. Please check the GitHub action log."

    if os.environ.get("SUBJECT"):
        msg = f'{os.environ.get("SUBJECT")}\n\n{msg}'

    if os.environ.get("GH_JOB"):
        msg += f'\n\n<a href="{os.environ.get("GH_JOB")}">{os.environ.get("GH_JOB")}</a>'

    payload = {
        "text": msg,
        "parse_mode": parse_mode,
        "disable_web_page_preview": False,
        "disable_notification": False,
        "reply_to_message_id": None,
        "chat_id": chat_id
    }
    headers = {
        "accept": "application/json",
        "User-Agent": "Python script",
        "content-type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)

    return response.text


if len(sys.argv) == 2:
    message = sys.argv[1]
else:
    message = sys.stdin.read()

if not message:
    sys.exit(0)

result = json.loads(sendMessage(message))
if not result["ok"]:
    print(result["error_code"], result["description"])
    sys.exit(1)
