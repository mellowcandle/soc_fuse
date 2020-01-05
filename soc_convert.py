#!/bin/env python3

# Header:
# u32 magic; // 0x57a32bcd
# u32 version; // 1
# char soc_name[32];
# u32 top_count;
# struct top[];

# top
# char top_name[32];
# u32 next_top_offset;
# u32 reg_count;
# struct reg[] regs;

# regs
# char name[64];
# u64 addr;
# u32 access_type



import json
import argparse
from struct import *

parser = argparse.ArgumentParser()
parser.add_argument('--input', '-i', type=argparse.FileType('r'), required=True)
parser.add_argument('--output', '-o', type=argparse.FileType('wb'), required=True)
options = parser.parse_args()

with options.input:
    try:
        obj = json.load(options.input)
    except ValueError as e:
        raise SystemExit(e)


print(type(obj))
print("Register lists count: %d" % len(obj['RegisterLists']))

# Write header
options.output.write(pack('<II32sI', 0x57a32bcd, 0x1, obj['Name'][:32].encode('ascii'), len(obj['RegisterLists'])))

#options.output.write(0x57a32bcd.to_bytes(4, byteorder='little'))
#options.output.write(0x1.to_bytes(4, byteorder='little'))
#options.output.write(obj['Name'].encode('ascii').to_bytes(32))
#print(json.dumps(obj, indent=2))
