#!/usr/bin/env python3
# Copyright (C) 2001-2026 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

"""Send a notification to a Microsoft Teams channel via a Teams "Workflows" webhook.

The message is taken from the first command-line argument or from stdin.

Environment variables:
    MSTEAMS_URL  (required) Teams "Workflows" webhook URL. Keep it in GitHub secrets only.
    SUBJECT      (optional) Message title.
    GH_JOB       (optional) Link to the GitHub Actions run, shown as a button.
"""

import requests
import sys
import os

webhook_url = os.environ.get("MSTEAMS_URL")  # Teams "Workflows" app webhook URL. env MSTEAMS_URL must be set!

if not webhook_url:
    print('Please set environmental variable "MSTEAMS_URL"')


def sendMessage(msg, passthrough=True):

    if passthrough:
        print(msg)

    if len(msg) == 0:
        return

    if len(msg) > 20000:
        msg = "Message output is too long. Please check the GitHub action log."

    header = [{
        "type": "TextBlock",
        "weight": "Bolder",
        "size": "Medium",
        "wrap": True,
        "text": os.environ.get("SUBJECT", "zabbix_utils notification")
    }]

    details = [{"type": "TextBlock", "wrap": True, "text": line or " "} for line in msg.splitlines()]

    actions = []
    if os.environ.get("GH_JOB"):
        actions.append({"type": "Action.OpenUrl", "title": "Open GitHub run", "url": os.environ.get("GH_JOB")})

    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "Container",
                        "style": "attention",
                        "bleed": True,
                        "items": header
                    },
                    *details
                ],
                "actions": actions
            }
        }]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=30)
    except requests.RequestException as error:
        # Print only the error type: the error text may contain parts of the webhook URL,
        # which GitHub would not mask in the (public) log.
        print(f"Failed to send the message to Microsoft Teams: {type(error).__name__}")
        sys.exit(1)

    if not response.ok:
        print(response.status_code, response.text)
        sys.exit(1)


if len(sys.argv) == 2:
    sendMessage(sys.argv[1])
else:
    sendMessage(sys.stdin.read())
