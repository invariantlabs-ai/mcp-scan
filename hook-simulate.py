"""
Reads a JSONL and feeds it to the hook-gateway.py script, as if Cursor was sending the hook payloads.
"""

import sys
import json
import subprocess
import uuid

conversation_id = str(uuid.uuid4())
generation_id = str(uuid.uuid4())

with open(sys.argv[1]) as f:
    for line in f:
        contents = line.split("]", 1)[1].strip()
        if len(contents) > 0:
            contents = json.loads(contents)
            contents["conversation_id"] = conversation_id
            contents["generation_id"] = generation_id
        # call python hook-gateway.py and feed contents as stdin
        result = subprocess.run(["python", "hook-gateway.py"], input=json.dumps(contents), capture_output=True, text=True)
        
        # print result
        print(result.stdout.strip())
