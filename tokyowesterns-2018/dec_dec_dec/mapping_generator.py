#!/usr/bin/env python

import itertools
import subprocess
import json
import string

BASE64_ALPHABET = list(string.ascii_letters) + list(string.digits) + ['+', '/']

# Generate all 3-character base64 codes
triplets = itertools.product(BASE64_ALPHABET, repeat=3)
inputs = [''.join(triplet) for triplet in triplets]
input_s = "\n".join(inputs)

# Send the input codes to the instrumentation process
p = subprocess.Popen(["./goop"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
outputs = p.communicate(input_s)[0].splitlines()[2:]

# Create mapping from output (in hex, skipping first character,
# which is always '#') to input (as string)
mapping = { k[1:].encode("hex"): v for k, v in zip(outputs, inputs) }

# Export to JSON
with open('mapping.json', 'w') as f:
    f.write(json.dumps(mapping))

