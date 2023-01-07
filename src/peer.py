import sys
import os
import time
import math
import matplotlib.pyplot as plt

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
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config = None
ex_output_file = None
ex_received_chunk = dict()

# 这个是下一次需要下载编号
expected_seq_num = dict()
SampleRTT = dict()
EstimatedRTT = dict()
DevRTT = dict()
TimeoutInterval = dict()

# 上一次发送RTT的时间
previous_time = dict()
congestion_window = dict()
tempcongestion_window = dict()
ssthresh = dict()
congestion_state = dict()
# 当前发送的最小的包
base = dict()
right_border = dict()
# 连续收到的相同的ack的个数
dup_ACK_count = dict()

sending_dict = dict()
receiving_dict = dict()
chunk_peer_dict = dict()
request_plan = dict()
who_has_start_time = None
have_send_who_has = False
download_file = None
response_num_of_who_has = 0
expect_response_num_of_who_has = 0
max_resend_who_has = 8
num_of_resend_who_has = 0
request_num = 0
receive_num = 0
get_dict = dict()

pre_timeout_is_set = None
pre_timeout = None

send_start_time = dict()
cwnd_time_record = dict()
cwnd_size_record = dict()
finished_send = dict()


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    # print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    global config
    global ex_output_file
    global ex_received_chunk

    # 这个是下一次需要下载编号
    global expected_seq_num
    global SampleRTT
    global EstimatedRTT
    global DevRTT
    global TimeoutInterval

    # 上一次发送RTT的时间
    global previous_time
    global congestion_window
    global tempcongestion_window
    global ssthresh
    global congestion_state
    # 当前发送的最小的包
    global base
    global right_border
    # 连续收到的相同的ack的个数
    global dup_ACK_count

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global max_resend_who_has
    global num_of_resend_who_has
    global request_num
    global receive_num
    global get_dict
    global pre_timeout_is_set
    global pre_timeout

    global send_start_time
    global cwnd_time_record
    global cwnd_size_record
    global finished_send

    ex_output_file = outputfile
    download_file = chunkfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        for line in cf:
            request_num += 1
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()

            chunk_peer_dict[datahash_str] = []
            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash = download_hash + datahash

            # Step2: make WHOHAS pkt
            # |2byte magic|1byte type |1byte team|
            # |2byte  header len  |2byte pkt len |
            # |      4byte  seq                  |
            # |      4byte  ack                  |
        whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt = whohas_header + download_hash

        # Step3: flooding whohas to all peers in peer list
        peer_list = config.peers
        for p in peer_list:
            if int(p[0]) != config.identity:
                request_plan[(p[1], int(p[2]))] = []
                sock.sendto(whohas_pkt, (p[1], int(p[2])))
                expect_response_num_of_who_has += 1
        who_has_start_time = time.time()


def process_inbound_udp(sock):
    # Receive pkt
    global config
    global ex_output_file
    global ex_received_chunk

    # 这个是下一次需要下载编号
    global expected_seq_num
    global SampleRTT
    global EstimatedRTT
    global DevRTT
    global TimeoutInterval

    # 上一次发送RTT的时间
    global previous_time
    global congestion_window
    global tempcongestion_window
    global ssthresh
    global congestion_state
    # 当前发送的最小的包
    global base
    global right_border
    # 连续收到的相同的ack的个数
    global dup_ACK_count

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global max_resend_who_has
    global num_of_resend_who_has
    global request_num
    global receive_num
    global get_dict
    global pre_timeout_is_set
    global pre_timeout

    global send_start_time
    global cwnd_time_record
    global cwnd_size_record
    global finished_send

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(
        "HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        peer_request_chunkhash_strs = []
        for i in range(len(data) // 20):
            whohas_chunk_hash = data[20 * i:20 * (i + 1)]
            # bytes to hex_str
            peer_request_chunkhash_strs.append(bytes.hex(whohas_chunk_hash))

        print(f"whohas: {peer_request_chunkhash_strs}, has: {list(config.haschunks.keys())}")
        ihavehash = bytes()
        for chunkhash_str in peer_request_chunkhash_strs:
            if chunkhash_str in config.haschunks:
                ihavehash += bytes.fromhex(chunkhash_str)
            # send back IHAVE pkt

        ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN),
                                   socket.htons(
                                       HEADER_LEN + len(ihavehash)), socket.htonl(0),
                                   socket.htonl(0))
        ihave_pkt = ihave_header + ihavehash
        sock.sendto(ihave_pkt, from_addr)

    elif Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        response_num_of_who_has += 1
        peerhas_chunkhash_strs = []
        for i in range(len(data) // 20):
            peerhas_chunk_hash = data[20 * i:20 * (i + 1)]
            peerhas_chunkhash_strs.append(bytes.hex(peerhas_chunk_hash))
        for peerhas_chunkhash_str in peerhas_chunkhash_strs:
            chunk_peer_dict[peerhas_chunkhash_str].append(from_addr)

    elif Type == 2:
        # received a GET pkt
        get_chunk_hash = data[:20]
        sending_dict[from_addr] = bytes.hex(get_chunk_hash)
        chunk_data = config.haschunks[sending_dict[from_addr]][:MAX_PAYLOAD]

        # 初始化发送方的变量
        if pre_timeout_is_set is False:
            SampleRTT[from_addr] = None
            EstimatedRTT[from_addr] = None
            DevRTT[from_addr] = None
            TimeoutInterval[from_addr] = 100000000
        else:
            TimeoutInterval[from_addr] = pre_timeout

        # 上一次发送RTT的时间
        congestion_window[from_addr] = 1
        tempcongestion_window[from_addr] = 1.0
        ssthresh[from_addr] = 64
        congestion_state[from_addr] = 0
        # 当前发送的最小的包
        base[from_addr] = 1
        right_border[from_addr] = 1
        # 连续收到的相同的ack的个数
        dup_ACK_count[from_addr] = 0
        send_start_time[from_addr] = time.time()
        cwnd_time_record[from_addr] = []
        cwnd_size_record[from_addr] = []
        finished_send[from_addr] = False
        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)
        previous_time[from_addr] = time.time()

    elif Type == 3:
        # 收到了对面传过来的一个data包
        # 首先判断这个data包是否是当前需要收的包
        # 如果是，收下来，然后发送ack
        # 如果不是，发送ack

        expected = expected_seq_num[from_addr]
        seq_sum = socket.ntohl(Seq)
        # 当前的包就是需要接受的包
        if expected == seq_sum:
            expected_seq_num[from_addr] += 1
            ex_received_chunk[receiving_dict[from_addr]] += data
            if socket.ntohl(Seq) == 1 and from_addr in get_dict:
                del get_dict[from_addr]
            # send back ACK
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN),
                                  0, Seq)
            sock.sendto(ack_pkt, from_addr)

            # see if finished
            if len(ex_received_chunk[receiving_dict[from_addr]]) == CHUNK_DATA_SIZE:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle

                # add to this peer's haschunk:
                config.haschunks[receiving_dict[from_addr]] = ex_received_chunk[receiving_dict[from_addr]]

                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                print(f"GOT {ex_output_file}")

                # The following things are just for illustration, you do not need to print out in your design.
                sha1 = hashlib.sha1()
                sha1.update(ex_received_chunk[receiving_dict[from_addr]])
                received_chunkhash_str = sha1.hexdigest()
                print(f"Expected chunkhash: {receiving_dict[from_addr]}")
                print(f"Received chunkhash: {received_chunkhash_str}")
                success = receiving_dict[from_addr] == received_chunkhash_str
                print(f"Successful received: {success}")
                if success:
                    print("Congrats! You have completed the example!")
                    print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
                    receive_num += 1
                    if (request_num == receive_num):
                        with open(ex_output_file, "wb") as wf:
                            pickle.dump(ex_received_chunk, wf)
                else:
                    print("Example fails. Please check the example files carefully.")
                del receiving_dict[from_addr]
                del request_plan[from_addr][0]
                if len(request_plan[from_addr]) > 0:
                    expected_seq_num[from_addr] = 1
                    get_chunk_hash = bytes.fromhex(request_plan[from_addr][0])
                    # send back GET pkt
                    get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                             socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                             socket.htonl(0))
                    get_pkt = get_header + get_chunk_hash
                    receiving_dict[from_addr] = bytes.hex(get_chunk_hash)
                    sock.sendto(get_pkt, from_addr)
                    get_dict[from_addr] = (get_chunk_hash, time.time())
        # 有可能之前的包收到了但ACK丢失了
        elif seq_sum < expected:
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN),
                                  0, socket.htonl(seq_sum))
            sock.sendto(ack_pkt, from_addr)
        # 当前的包不是我们需要接受的包
        # 我们就返回
        else:
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN),
                                  0, socket.htonl(expected - 1))
            sock.sendto(ack_pkt, from_addr)

    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        if finished_send[from_addr] is False:
            if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                finished_send[from_addr] = True
                print(f"finished sending {sending_dict[from_addr]}")
                plt.show()
                del sending_dict[from_addr]
                # 上一次发送RTT的时间
                del previous_time[from_addr]
                del congestion_window[from_addr]
                del tempcongestion_window[from_addr]
                del ssthresh[from_addr]
                del congestion_state[from_addr]
                # 当前发送的最小的包
                del base[from_addr]
                del right_border[from_addr]
                # 连续收到的相同的ack的个数
                del dup_ACK_count[from_addr]
                if pre_timeout_is_set is False:
                    del SampleRTT[from_addr]
                    del EstimatedRTT[from_addr]
                    del DevRTT[from_addr]
                del TimeoutInterval[from_addr]

            # 如果ack + 1是当前发送最小的包
            elif ack_num + 1 == base[from_addr]:
                dup_ACK_count[from_addr] += 1
                if dup_ACK_count[from_addr] == 3:
                    ssthresh[from_addr] = max(congestion_window[from_addr] // 2, 2)
                    congestion_window[from_addr] = 1
                    tempcongestion_window[from_addr] = 1.0
                    congestion_state[from_addr] = 0
                    right_border[from_addr] = base[from_addr]
                    send_data(sock, ack_num, from_addr)
            elif ack_num >= base[from_addr]:
                base[from_addr] = ack_num + 1
                updateWindow(from_addr)
                if pre_timeout_is_set is False:
                    updateTimeout(from_addr)
                previous_time[from_addr] = time.time()
                dup_ACK_count[from_addr] = 0
                pre_right_border = right_border[from_addr]
                for i in range(pre_right_border + 1, base[from_addr] + congestion_window[from_addr]):
                    next_packet = i
                    if (next_packet - 1) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                        break
                    right_border[from_addr] = i
                    send_data(sock, next_packet - 1, from_addr)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    global ex_output_file
    global ex_received_chunk

    # 这个是下一次需要下载编号
    global expected_seq_num
    global SampleRTT
    global EstimatedRTT
    global DevRTT
    global TimeoutInterval

    # 上一次发送RTT的时间
    global previous_time
    global congestion_window
    global tempcongestion_window
    global ssthresh
    global congestion_state
    # 当前发送的最小的包
    global base
    global right
    # 连续收到的相同的ack的个数
    global dup_ACK_count

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global max_resend_who_has
    global num_of_resend_who_has
    global request_num
    global receive_num
    global get_dict
    global pre_timeout_is_set
    global pre_timeout

    global send_start_time
    global cwnd_time_record
    global cwnd_size_record
    global finished_send

    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)
    if config.timeout != 0:
        pre_timeout_is_set = True
        pre_timeout = config.timeout
    else:
        pre_timeout_is_set = False
    try:
        limit_time = 2
        while True:
            # 如果当前没有发送who has包
            if have_send_who_has is False:
                # 如果设置了who has的时间，就代表准备发送who has的包
                if who_has_start_time is not None:
                    # 如果当前时间和who has发送包的时间大于2
                    if time.time() - who_has_start_time > 2:
                        # 如果当前已经收到所有的response
                        if response_num_of_who_has == expect_response_num_of_who_has or num_of_resend_who_has >= max_resend_who_has:
                            # 对所有的response进行配合
                            decide_request_plan(sock)
                            have_send_who_has = True
                        else:
                            # 重新发送
                            resend_who_has(sock)

            if who_has_start_time is not None and time.time() - who_has_start_time > limit_time:
                limit_time *= 2
                resend_who_has(sock)

            # 检查get包是否都成功发送
            if len(get_dict) != 0:
                resend_get(sock)

            # 检查RTT是否超时
            now_time = time.time()
            for peer in sending_dict:
                if now_time - previous_time[peer] > TimeoutInterval[peer]:
                    previous_time[peer] = time.time()
                    ssthresh[peer] = max(congestion_window[peer] // 2, 2)
                    congestion_window[peer] = 1
                    tempcongestion_window[peer] = 1.0
                    congestion_state[peer] = 0
                    right_border[peer] = base[peer]
                    # 发送最小包
                    ack_num = base[peer] - 1
                    left = (ack_num) * MAX_PAYLOAD
                    right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    next_data = config.haschunks[sending_dict[peer]][left: right]
                    # send next data
                    data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                              socket.htons(HEADER_LEN + len(next_data)),
                                              socket.htonl(ack_num + 1), 0)
                    sock.sendto(data_header + next_data, peer)

            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    # 收到回复了
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        # 画图
        for from_addr in cwnd_time_record:
            plt.plot(cwnd_time_record[from_addr], cwnd_size_record[from_addr], color='blue')
            plt.xlabel("Time(s)")
            plt.ylabel("Window Size")
            plt.title("Sending Window Size")
            plt.savefig('cwnd.png')
            plt.show()
        sock.close()


def decide_request_plan(sock):
    global config
    global ex_output_file
    global ex_received_chunk

    # 这个是下一次需要下载编号
    global expected_seq_num
    global SampleRTT
    global EstimatedRTT
    global DevRTT
    global TimeoutInterval

    # 上一次发送RTT的时间
    global previous_time
    global congestion_window
    global tempcongestion_window
    global ssthresh
    global congestion_state
    # 当前发送的最小的包
    global base
    global right
    # 连续收到的相同的ack的个数
    global dup_ACK_count

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global max_resend_who_has
    global num_of_resend_who_has
    global request_num
    global receive_num
    global get_dict
    global pre_timeout_is_set
    global pre_timeout

    global send_start_time
    global cwnd_time_record
    global cwnd_size_record
    global finished_send

    temp = []
    for chunk in chunk_peer_dict:
        temp.append((len(chunk_peer_dict[chunk]), chunk))
    temp.sort()
    for element in temp:
        chunk = element[1]
        min = 1000000000
        choice = None
        for peer in chunk_peer_dict[chunk]:
            if len(request_plan[peer]) < min:
                min = len(request_plan[peer])
                choice = peer
        if choice is not None:
            request_plan[choice].append(chunk)

    # 到这里完成了所有的挑选，并向对方发送了一个GET请求
    for peer in request_plan:
        if len(request_plan[peer]) > 0:
            expected_seq_num[peer] = 1
            get_chunk_hash = bytes.fromhex(request_plan[peer][0])
            # send back GET pkt
            get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                     socket.htonl(0))
            get_pkt = get_header + get_chunk_hash
            receiving_dict[peer] = bytes.hex(get_chunk_hash)
            sock.sendto(get_pkt, peer)
            get_dict[peer] = (get_chunk_hash, time.time())
    print(request_plan)
    print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n")


def resend_who_has(sock):
    global config
    global ex_output_file
    global ex_received_chunk

    # 这个是下一次需要下载编号
    global expected_seq_num
    global SampleRTT
    global EstimatedRTT
    global DevRTT
    global TimeoutInterval

    # 上一次发送RTT的时间
    global previous_time
    global congestion_window
    global tempcongestion_window
    global ssthresh
    global congestion_state
    # 当前发送的最小的包
    global base
    global right
    # 连续收到的相同的ack的个数
    global dup_ACK_count

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global max_resend_who_has
    global num_of_resend_who_has
    global request_num
    global receive_num
    global get_dict
    global pre_timeout_is_set
    global pre_timeout

    global send_start_time
    global cwnd_time_record
    global cwnd_size_record
    global finished_send

    ex_received_chunk = dict()

    receiving_dict = dict()
    chunk_peer_dict = dict()
    request_plan = dict()
    who_has_start_time = None
    have_send_who_has = False
    response_num_of_who_has = 0
    expect_response_num_of_who_has = 0
    request_num = 0
    receive_num = 0
    get_dict = dict()
    num_of_resend_who_has += 1

    download_hash = bytes()
    with open(download_file, 'r') as cf:
        for line in cf:
            request_num += 1
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()
            chunk_peer_dict[datahash_str] = []
            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash = download_hash + datahash

            # Step2: make WHOHAS pkt
            # |2byte magic|1byte type |1byte team|
            # |2byte  header len  |2byte pkt len |
            # |      4byte  seq                  |
            # |      4byte  ack                  |
        whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt = whohas_header + download_hash

        # Step3: flooding whohas to all peers in peer list
        peer_list = config.peers
        for p in peer_list:
            if int(p[0]) != config.identity:
                request_plan[(p[1], int(p[2]))] = []
                sock.sendto(whohas_pkt, (p[1], int(p[2])))
                expect_response_num_of_who_has += 1
        who_has_start_time = time.time()


def resend_get(sock):
    global receiving_dict
    global get_dict

    now_time = time.time()
    for peer in get_dict:
        send_time = get_dict[peer][1]
        if now_time - send_time > 2:
            get_chunk_hash = get_dict[peer][0]
            # send back GET pkt
            get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                     socket.htonl(0))
            get_pkt = get_header + get_chunk_hash
            receiving_dict[peer] = bytes.hex(get_chunk_hash)
            sock.sendto(get_pkt, peer)
            get_dict[peer] = (get_chunk_hash, time.time())


def send_data(sock, ack_num, from_addr):
    left = (ack_num) * MAX_PAYLOAD
    right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
    next_data = config.haschunks[sending_dict[from_addr]][left: right]
    # send next data
    data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                              socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
    sock.sendto(data_header + next_data, from_addr)


# 更新timeout
def updateTimeout(from_addr):
    if SampleRTT[from_addr] is None:
        SampleRTT[from_addr] = time.time() - previous_time[from_addr]
        EstimatedRTT[from_addr] = SampleRTT[from_addr]
        DevRTT[from_addr] = 0.0
        TimeoutInterval[from_addr] = SampleRTT[from_addr]
    else:
        SampleRTT[from_addr] = time.time() - previous_time[from_addr]
        EstimatedRTT[from_addr] = 0.875 * EstimatedRTT[from_addr] + 0.125 * SampleRTT[from_addr]
        DevRTT[from_addr] = 0.75 * DevRTT[from_addr] + 0.25 * abs(SampleRTT[from_addr] - EstimatedRTT[from_addr])
        TimeoutInterval[from_addr] = EstimatedRTT[from_addr] + 4 * DevRTT[from_addr]


# 更新window
def updateWindow(from_addr):
    if congestion_state[from_addr] == 0:
        congestion_window[from_addr] += 1
        tempcongestion_window[from_addr] += 1.0
        if (congestion_window[from_addr]) >= ssthresh[from_addr]:
            congestion_state[from_addr] = 1
        cwnd_time_record[from_addr].append(time.time() - send_start_time[from_addr])
        cwnd_size_record[from_addr].append(congestion_window[from_addr])
    else:
        temp = congestion_window[from_addr]
        tempcongestion_window[from_addr] += 1 / tempcongestion_window[from_addr]
        congestion_window[from_addr] = math.floor(tempcongestion_window[from_addr])
        if congestion_window[from_addr] != temp:
            cwnd_time_record[from_addr].append(time.time() - send_start_time[from_addr])
            cwnd_size_record[from_addr].append(congestion_window[from_addr])


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument(
        '-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument(
        '-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument(
        '-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
