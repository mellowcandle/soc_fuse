#!/bin/env python3

# Header: (44bytes)
# u32 magic; // 0x57a32bcd
# u32 version; // 1
# char soc_name[32];
# u32 top_count;
# struct top[];

# top (32 + 4 + 4)
# char top_name[32];
# u32 reg_count;
# u32 next_top_offset;
# struct reg[] regs;

# regs (64 + 8 + 4)
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

# Write header
options.output.write(pack('<II32sI', 0x57a32bcd, 0x1, obj['Name'][:32].encode('ascii'), len(obj['RegisterLists'])))

offset = 44

for top in obj['RegisterLists']:
    # Write top header:
    offset = offset + 40 + (len(top['Registers']) * 76)
    options.output.write(pack('<32sII', top['Name'][:32].encode('ascii'), len(top['Registers']), offset))

    for register in top['Registers']:
        # Meanwhile we treat all regsiters as 32bit wide, which is wrong but it's difficult to detect it without
        # diving to the bits, which is I don't want to do now.
        options.output.write(pack('<64sqI', register['Name'][:64].encode('ascii'), int(register['Address'], 16), 32))

