#!/usr/bin/env python3

# ----- Import libraries, global settings -----

from math import floor, sqrt
from PIL import Image

DEBUG_LOGGING = True

if DEBUG_LOGGING:
    import struct
try:
    import numpy as np
    USE_NUMPY = True
except ImportError:
    USE_NUMPY = False

USE_NUMPY = False

# ----- Extracted constants -----

# These constants are used as weights for each differently-sized
# rectangle during the feature extraction phase.
# This is used in Equation 11 in the paper.
WEIGHT_R1 = float.fromhex('0x1.936398bf0aae3p-3')
WEIGHT_R2 = float.fromhex('0x1.caddcd96f4881p-2')
WEIGHT_R3 = float.fromhex('0x1.1cb5cf620ef1dp-2')

# This is used for initial hash scaling.
# This is described in section 3.4 of the paper.
HASH_SCALE_CONST = float.fromhex('0x1.07b3705abb25cp0')

# ----- Put it all together -----


def compute_hash(filename):
    im = Image.open(filename)
    print(im)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} filename")
        sys.exit(-1)
    compute_hash(sys.argv[1])
