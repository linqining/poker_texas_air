#!/usr/bin/env python3
import sys, re
text = sys.stdin.read()
kind = sys.argv[1]
patterns = {
    "addr": r"Contract Address:\s*(0x[0-9a-fA-F]+)",
    "class": r"[Cc]lass [Hh]ash:\s*(0x[0-9a-fA-F]+)",
    "tx": r"Transaction Hash:\s*(0x[0-9a-fA-F]+)",
    "already": r"class hash (0x[0-9a-fA-F]+)",
}
m = re.search(patterns[kind], text)
print(m.group(1).lower() if m else "")
