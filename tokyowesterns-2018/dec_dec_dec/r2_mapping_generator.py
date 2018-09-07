#!/usr/bin/env python3

from base64 import b64encode
import struct
import string
import itertools
import subprocess
from binascii import unhexlify
import json
from concurrent import futures

MAX_WORKERS = 10

def f(s):
    ram = 'ABC'*4 + s + 'D'*17
    arg1 = 'B' * 24
    command = 'echo "dcu 0x5555555550ef; w {} @ 0x5555557572c0; dcu 0x5555555550f4; px 45 @ 0x5555557572f0+1" | r2 -e scr.color=false -d -Raslr=no -Rarg1={} dec_dec_dec-c55c231bfbf686ab058bac2a56ce6cc49ae32fe086af499571e335c9f7417e5b 2>&1 | grep 0x555555757301 | cut -d\' \' -f3-4'.format(ram, arg1)
    ret = subprocess.check_output(["sh", "-c", command])
    ret = ret.strip().replace(b' ',b'')
    return (s, unhexlify(ret).hex())

alphabet = [c for c in string.ascii_letters] + [c for c in string.digits] + ['+','/']

mapping = {}
x = 0
triplets = itertools.product(alphabet, repeat=3)

with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    all_futures = (executor.submit(f, ''.join(t)) for t in triplets)
    print("JOBS SUBMITTED!!!!!")
    for future in futures.as_completed(all_futures):
        (s, ret) = future.result()
        mapping[ret] = s
        x += 1
        if x % 100 == 0:
            print(x)

with open('mapping.json', 'w') as f:
    f.write(json.dumps(mapping))
