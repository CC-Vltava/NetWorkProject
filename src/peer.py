import sys
import os
import time

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
requset_num = 0
receive_num = 0
get_dict = dict()


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    # print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    global config
    global ex_output_file
    global ex_received_chunk

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global requset_num
    global receive_num
    ex_output_file = outputfile
    download_file = chunkfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        for line in cf:
            requset_num += 1
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

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global requset_num
    global receive_num
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

        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)

    elif Type == 3:
        # received a DATA pkt
        ex_received_chunk[receiving_dict[from_addr]] += data
        if socket.ntohl(Seq) == 1:
            del get_dict[from_addr]
        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
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
                if (requset_num == receive_num):
                    with open(ex_output_file, "wb") as wf:
                        pickle.dump(ex_received_chunk, wf)
            else:
                print("Example fails. Please check the example files carefully.")
            del receiving_dict[from_addr]
            del request_plan[from_addr][0]
            if len(request_plan[from_addr]) > 0:
                get_chunk_hash = bytes.fromhex(request_plan[from_addr][0])
                # send back GET pkt
                get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + get_chunk_hash
                receiving_dict[from_addr] = bytes.hex(get_chunk_hash)
                sock.sendto(get_pkt, from_addr)
                get_dict[from_addr] = (get_chunk_hash, time.time())

    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {sending_dict[from_addr]}")
            del sending_dict[from_addr]
            pass
        else:
            left = (ack_num) * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            next_data = config.haschunks[sending_dict[from_addr]][left: right]
            # send next data
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
    global ex_output_file
    global ex_received_chunk

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global requset_num
    global receive_num
    global max_resend_who_has
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            if have_send_who_has is False:
                if who_has_start_time is not None:
                    if time.time() - who_has_start_time > 2:
                        if response_num_of_who_has == expect_response_num_of_who_has or num_of_resend_who_has >= max_resend_who_has:
                            decide_request_plan(sock)
                            have_send_who_has = True
                        else:
                            resend_who_has(sock)
            if len(get_dict) != 0:
                resend_get(sock)
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def decide_request_plan(sock):
    global config
    global ex_output_file
    global ex_received_chunk

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global requset_num
    global receive_num
    global get_dict
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
    for peer in request_plan:
        if len(request_plan[peer]) > 0:
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

    global sending_dict
    global receiving_dict
    global chunk_peer_dict
    global request_plan
    global who_has_start_time
    global have_send_who_has
    global download_file
    global response_num_of_who_has
    global expect_response_num_of_who_has
    global requset_num
    global receive_num
    global num_of_resend_who_has
    ex_received_chunk = dict()

    sending_dict = dict()
    receiving_dict = dict()
    chunk_peer_dict = dict()
    request_plan = dict()
    who_has_start_time = None
    have_send_who_has = False
    response_num_of_who_has = 0
    expect_response_num_of_who_has = 0
    requset_num = 0
    receive_num = 0
    download_hash = bytes()
    num_of_resend_who_has += 1
    with open(download_file, 'r') as cf:
        for line in cf:
            requset_num += 1
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
