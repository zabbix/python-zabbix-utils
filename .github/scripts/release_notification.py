#!/usr/bin/env python
# coding: utf-8

import os
import json
import smtplib
import markdown

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Repository constants
LIBRARY_VERSION = os.environ['LIBRARY_VERSION']
REPOSITORY = os.environ['REPOSITORY']

# Mail server variables
mail_port = int(os.environ.get('MAIL_PORT', '465'))
mail_server = os.environ['MAIL_SERVER']
auth_user = os.environ['MAIL_USER']
auth_pass = os.environ['MAIL_PASS']

# Mail variables
mail_from = '"zabbix_utils" <' + auth_user + '>'
mail_to = json.loads(os.environ['RELEASE_RECIPIENT_LIST'])
mail_subject = f"[GitHub] A new version {LIBRARY_VERSION} of the zabbix_utils library has been released"
mail_text = f"""<strong>
    A new version of the zabbix_utils library has been released: 
    <a href="https://github.com/{REPOSITORY}/releases/tag/v{LIBRARY_VERSION}">v{LIBRARY_VERSION}</a>
</strong>
<br><br>
"""

# Reading release notes
with open("RELEASE_NOTES.md", "r", encoding="utf-8") as fh:
    release_notes = markdown.markdown("\n".join(fh.readlines()[1:]))

# Preparing mail data
msg = MIMEMultipart('mixed')
msg['Subject'] = mail_subject
msg['From'] = mail_from
msg['To'] = ', '.join(mail_to)

# Adding message text
msg.attach(MIMEText(mail_text + release_notes, 'html'))

# Connection to the mail server
server = smtplib.SMTP_SSL(mail_server, mail_port)
server.login(auth_user, auth_pass)

# Sending email
server.sendmail(mail_from, mail_to, msg.as_string())

# Closing connection
server.quit()
