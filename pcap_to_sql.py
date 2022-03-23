from pcapng import FileScanner
import re, sys
from pcapng.blocks import EnhancedPacket

with open(sys.argv[1], 'rb') as fp:
    scanner = FileScanner(fp)
    for block in scanner:
        if(isinstance(block,EnhancedPacket)):
            s = block.packet_data.decode("ascii", errors='ignore')
            s = re.sub(r'[^a-zA-Z0-9\'\' ()]', '', s)
            print(s)
            