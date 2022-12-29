import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse

"""
This is an example on how to use the provided skeleton code.
Please note that this receiver will only download 1 chunk from the sender as we only maintain ONE downloading process.
You are advised to focus the following things:
1. How to make a pkt using struct?
2. How to send/receive pkt with simsocket?
3. How to interpret bytes and how to adapt bytes to/from network endian?
4. How to use hashlib?
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config = None
ex_sending_chunkhash = ""


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    # print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    # This method will not be called in sender


def process_inbound_udp(sock):
    # Receive pkt
    global config
    global ex_sending_chunkhash

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]

    # 收到WHO HAS packet
    if Type == 0:
        # received an WHOHAS pkt
        # 这里因为只需要一个chunk，所以直接拿前20个byte
        whohas_chunk_hash = data[:20]
        # 将hash从16进制换成byte
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        ex_sending_chunkhash = chunkhash_str

        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        # 在config.haschunks里面找本地是否有haschunks
        if chunkhash_str in config.haschunks:
            # 发回 IHAVE pkt
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1,
                                       socket.htons(HEADER_LEN), socket.htons(HEADER_LEN + len(whohas_chunk_hash)),
                                       socket.htonl(0), socket.htonl(0))
            ihave_pkt = ihave_header + whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)

    # 收到GET packet
    elif Type == 2:
        # received a GET pkt
        # 从本地config.haschunks中获得对应data
        # 注意这里获得的是一部分的data而不是全部的data，一次发送的大小只有MAX_PAYLOAD
        # 这里是因为发送的chuck较大，所以可以直接用MAX_PAYLOAD，否则可能会越界
        chunk_data = config.haschunks[ex_sending_chunkhash][:MAX_PAYLOAD]

        # 发送 DATA，注意需要sequence和ACK的值！
        data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)

    # 收到 ACK packet
    elif Type == 4:
        # received an ACK pkt
        # 获取ACK的值
        ack_num = socket.ntohl(Ack)
        # 用当前收到的个数 * 每个chunk的大小来判断是否发送完成
        if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {ex_sending_chunkhash}")
            pass
        else:
            # 没有完成的时候，判断下一次发送的数据范围
            left = (ack_num) * MAX_PAYLOAD
            # 这里就对right进行了处理，防止越界
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash][left: right]
            # 发送下一个data信息，同时注意ack和sequence
            data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
            sock.sendto(data_header + next_data, from_addr)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                # 这里就只需要处理其他socket发来的消息
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    # process_user_input(sock)
                    # Sender do not need to handle user input
                    pass
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
