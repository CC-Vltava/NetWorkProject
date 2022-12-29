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
import pickle

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

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_downloading_chunkhash = ""

# 一个chunk 512 bytes
# 一个chunk的hash是20bytes
def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    # print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash

    # 设置输出的路径
    ex_output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    # 这个将下载hash设置为空
    download_hash = bytes()
    # 打开下载文件
    with open(chunkfile, 'r') as cf:
        index, datahash_str = cf.readline().strip().split(" ")
        # 将当前所有需要接收的块的received chunk设置为空
        ex_received_chunk[datahash_str] = bytes()
        # 将当前hash赋值到ex_downloading_chunkhash（暂时没发现这个有啥用）
        # 这个因为只需要下载一个chunk，所以直接把这个chunk的hash存在这里了
        ex_downloading_chunkhash = datahash_str

        # 将原有的16进制的chunk hash转为byte然后存放到download hash中
        datahash = bytes.fromhex(datahash_str)
        download_hash = download_hash + datahash

    # 这个是询问其他peer谁有想要的pkt
    # 注意htons函数，packet需要按照大端序来排列，所以一个位置如果存放大于1byte的信息，就需要使用htons来调整位置
    # 如果只有1byte的话，就没有大端序和小端序的问题，也就不用使用htons了
    # Step2: make WHOHAS pkt
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0,
                                socket.htons(HEADER_LEN), socket.htons(HEADER_LEN + len(download_hash)),
                                socket.htonl(0), socket.htonl(0))
    # 头部没什么说的，中间的部分就直接把需要下载的download hash放进去就好了
    # 注意，download hash是所有需要的chunk的hash值组成的
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    # 获得所有的用户
    peer_list = config.peers
    # 遍历每一个用户
    for p in peer_list:
        # 如果用户
        if int(p[0]) != config.identity:
            # 由当前socket发送至对方的socket
            # 由于是UDP传送，所以只需要对方ip和port
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock):
    # 收到来自对方发来的packet
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    # 解压头部
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    # 因为data部分是直接存放的，所以直接拿出来就行了
    data = pkt[HEADER_LEN:]
    # 下面就是对每一种type的判断了
    if Type == 1:
        # 收到 IHAVE packet
        # see what chunk the sender has
        # 因为这里只要求下载一个chunk，所以直接用前20bytes获得chunk_hash
        get_chunk_hash = data[:20]
        # 直接发送GET请求，下载对应的文件
        get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header + get_chunk_hash
        # 发送GET单个的chunk hash请求给对面
        sock.sendto(get_pkt, from_addr)
    elif Type == 3:
        # 收到 DATA packet
        # 因为只需要下载一个chunk，所以直接把之前存hash的ex_downloading_chunkhash拿来用了
        ex_received_chunk[ex_downloading_chunkhash] += data
        # 收到data之后，就可以发送得到的消息，也就是发送ACK
        # 注意，这里的ack的值就是传过来的Seq
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4,
                              socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, Seq)
        sock.sendto(ack_pkt, from_addr)

        # 判断当前chunk是否收到完整了
        # 然后后面就是文件输出部分了
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)

            # add to this peer's haschunk:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = ex_downloading_chunkhash == received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")


def process_user_input(sock):
    # 指令 想要下载的文件 存储的路径
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        # 下载指令
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
                if sock in read_ready:
                    # 收到来自其他人的sock
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    # 收到外部的输入（这个就是下载的指令）
                    process_user_input(sock)
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
