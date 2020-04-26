import socket, struct, binascii

sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
try:
    while True:

        packet = sock.recvfrom(65565)

        eth_frame = packet[0][0:14] # L2 ISO OSI
        ip_header = packet[0][14:34] # L3 ISO OSI
        tcp_header = packet[0][34:54] # L4 ISO OSI

        eth = struct.unpack("!6s6sH",eth_frame)
        ip = struct.unpack("!12s4s4s", ip_header)
        tcp = struct.unpack("!HH9sB6s", tcp_header)

        dst_mac = binascii.hexlify(eth[0])
        src_mac = binascii.hexlify(eth[1])

        dst_mac = ':'.join(format(s, '02x') for s in bytes.fromhex(dst_mac.decode("utf-8")))
        src_mac = ':'.join(format(s, '02x') for s in bytes.fromhex(src_mac.decode("utf-8")))

        print("---> Start packet")
        print("Src. MAC             Dst MAC              Src IP                 Dst IP")
        print(src_mac,"  ",dst_mac,"  ",socket.inet_ntoa(ip[1]),":",tcp[0],"  ", socket.inet_ntoa(ip[2]),":",tcp[0])
        print("<--- End packet\n")

except KeyboardInterrupt:
    print("  Thank you for using Raw Data Packet Capture!")
