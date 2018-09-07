#!/usr/bin/env python3

import json
import codecs
import base64

MAPPING_FILENAME = "./mapping.json"

# 0x000011c8  4032 352d 5134 3445 3233 333d 2c3e 452d  @25-Q44E233=,>E-
# 0x000011d8  4d33 343d 2c2c 244c 5335 5645 5134 3529  M34=,,$LS5VEQ45)
# 0x000011e8  4d32 532d 292c 372d 242f 3354 2000 0000  M2S-),7-$/3T ...

# Taken from string constant in binary
ciphertext = "32352d513434453233333d2c3e452d4d33343d2c2c244c53355645513435294d32532d292c372d242f3354"

# From https://stackoverflow.com/a/312464
def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

with open(MAPPING_FILENAME, 'rb') as f:
    mapping = json.load(f)
    target_chunks = chunks(ciphertext, 4 * 2)

base64_text = ""
for chunk in target_chunks:
    try:
        # Remove last layer of encoding
        p1 = mapping[chunk]

        # Remove rot-13
        p2 = codecs.encode(p1, 'rot_13')

        base64_text += p2
    except KeyError as e:
        print("Warning: missing mapping for {}".format(e))
        pass

print("Recovered base64 text: ", base64_text)

# Pad to correct length
base64_text += "=" * (len(base64_text) % 4)

# Remove base64 encoding
plaintext = base64.b64decode(base64_text)

print("Recovered flag: ", plaintext)

