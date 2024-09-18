#!/bin/bash

mode=$1
class=$2
error=$3

cmd="import sys; sys.path.append('.'); from zabbix_utils import $class; $class()"
if [ $mode == "async" ]; then
    cmd="import sys; import asyncio; sys.path.append('.'); from zabbix_utils import $class; exec('async def main():\n    $class()'); asyncio.run(main())"
fi

result=$(python3 -c "$cmd" 2>&1)
echo "$result" | grep "$error" >/dev/null || echo "$result" | (python3 "./.github/scripts/telegram_msg.py" && echo "Error")
