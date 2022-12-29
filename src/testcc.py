import struct
import socket
print(struct.pack(">H", 123))
print(struct.pack("H", socket.htons(123)))
