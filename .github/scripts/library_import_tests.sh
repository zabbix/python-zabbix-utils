#!/bin/bash

class=$1
error=$2

result=$(python3 -c "import sys; sys.path.append('.'); from zabbix_utils import $class; $class()" 2>&1)
echo "$result" | grep "$error" >/dev/null || echo "$result" | (python3 "./.github/scripts/telegram_msg.py" && echo "Error")
