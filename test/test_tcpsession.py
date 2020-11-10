#!/usr/bin/env python3
# -*- coding: ISO-8859-15 -*-

import dpkt
import copy
import random
import os
import binascii
import shutil
from tcpsession.tcpsession import *

s_mac = b"\x00\x86\x9c\xcb\x29\x44"
d_mac = b"\x02\x1a\xc5\x01\x14\xb5"
sip = b'\x01\x02\x03\x04'
dip = b'\x01\x02\x04\x04'
ip_id = random.randint(0, 0xffff)
ip_id = 0x1337
p_tcp = 6
p_udp = 17
sport = 56332
dport = 80
c_start_seq_num = 0xdeadbeef
s_start_seq_num = 0xbeefdead
c_start_timestamp_val = 0x0b6fde6a
s_start_timestamp_val = 0xc232f947
# Flag is set by default

"""



    ******************************Warning**************************************



    Header checksum of the packets generated will not be right, since we are duplicating the packets.
    Goal here is to test the TCP flow, and that retransmitted packets get processed by both the ends correctly.
"""
t_first_syn_pkt = create_tcp_pkt(s_mac, d_mac, sip, dip, ip_id, sport, dport)
t_first_syn_pkt.data.data.seq = c_start_seq_num

syn_ack_flag = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
syn_ack_pkt = create_tcp_pkt(s_mac, d_mac, dip, sip, ip_id, dport, sport, syn_ack_flag)

t_syn_ack_pkt = copy.deepcopy(syn_ack_pkt)
t_syn_ack_pkt.data.data.seq = s_start_seq_num
t_syn_ack_pkt.data.data.ack = t_first_syn_pkt.data.data.seq + 1

t_c_first_ack_pkt = copy.deepcopy(t_first_syn_pkt)
t_c_first_ack_pkt.data.data.seq = t_syn_ack_pkt.data.data.ack
t_c_first_ack_pkt.data.data.ack = t_syn_ack_pkt.data.data.seq + 1
t_c_first_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK

t_c_sec_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
t_c_sec_ack_pkt.data.data.seq = t_c_first_ack_pkt.data.data.seq

t_s_sec_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
t_s_sec_ack_pkt.data.data.seq = t_c_first_ack_pkt.data.data.ack

t_c_rst_pkt = create_tcp_pkt(s_mac, d_mac, sip, dip, ip_id, sport, dport, dpkt.tcp.TH_RST)
t_s_rst_pkt = create_tcp_pkt(s_mac, d_mac, dip, sip, ip_id, dport, sport, dpkt.tcp.TH_RST)

t_c_fin_pkt = create_tcp_pkt(s_mac, d_mac, sip, dip, ip_id, sport, dport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
t_s_fin_pkt = create_tcp_pkt(s_mac, d_mac, dip, sip, ip_id, dport, sport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)


def tcp_hand_shake(debug=False):
    tcpsession = TCPSession("", sip, dip, sport, dport)
    if debug:
        tcpsession.set_print_debug_info()
    tcpsession._process(t_first_syn_pkt.pack())
    tcpsession._process(t_syn_ack_pkt.pack())
    tcpsession._process(t_c_first_ack_pkt.pack())
    return tcpsession


def test_tcp_handshake():
    tcpsession = TCPSession("", sip, dip, sport, dport)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.LISTENING
    tcpsession._process(t_first_syn_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.SYN_SENT
    assert s_state == TCPState.SYN_RECEIVED

    tcpsession._process(syn_ack_pkt.pack())
    tcpsession._process(t_first_syn_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.SYN_SENT
    assert s_state == TCPState.SYN_RECEIVED

    tcpsession._process(t_syn_ack_pkt.pack())
    tcpsession._process(t_syn_ack_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.SYN_SENT
    assert s_state == TCPState.SYN_RECEIVED

    tcpsession._process(t_c_first_ack_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED
    assert s_state == TCPState.ESTABLISHED
    assert (dpkt.ethernet.Ethernet(tcp_fix_checksum_buf(t_c_first_ack_pkt.pack())).data.data.sum ==
            tcp_fix_checksum(t_c_first_ack_pkt).data.data.sum)
    assert tcp_fix_checksum(None) is None

    tcpsession._process(t_c_rst_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED
    assert s_state == TCPState.CLOSED

    tcpsession = tcp_hand_shake()
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED
    assert s_state == TCPState.ESTABLISHED
    tcpsession._process(t_s_rst_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED
    assert s_state == TCPState.CLOSED


def test_slide_window():
    tcpsession = tcp_hand_shake()
    # test data from client to server
    payload_len = 50
    c_sec_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_sec_ack_pkt.data.data.data = b'\x41' * payload_len
    c_sec_ack_pkt.data.len += payload_len
    tcpsession._process(c_sec_ack_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED
    assert tcpsession.get_session_count() == 1
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 4
    # test retransmission, it should be ignored
    tcpsession._process(c_sec_ack_pkt.pack())
    tcpsession._process(c_sec_ack_pkt.pack())
    assert len(sessions[1]) == 4

    # test sending further data
    c_sec_ack_pkt.data.data.data = b'\x42' * payload_len
    c_sec_ack_pkt.data.data.seq += payload_len
    c_sec_ack_pkt = tcp_fix_checksum(c_sec_ack_pkt)
    tcpsession._process(c_sec_ack_pkt.pack())
    assert len(sessions[1]) == 5

    # test server acknowledgement
    s_sec_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    # s_sec_ack_pkt = dpkt.ethernet.Ethernet(t_s_sec_ack_pkt.pack())
    last_ack_by_client = s_sec_ack_pkt.data.data.seq
    s_sec_ack_pkt.data.data.ack += 2 * payload_len
    s_sec_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    tcpsession._process(s_sec_ack_pkt.pack())
    assert s_sec_ack_pkt.data.data.seq == c_sec_ack_pkt.data.data.ack
    assert len(sessions[1]) == 6

    # test server retransmission of acknowledgement
    tcpsession._process(s_sec_ack_pkt.pack())
    assert s_sec_ack_pkt.data.data.seq == c_sec_ack_pkt.data.data.ack
    assert len(sessions[1]) == 6

    # test server sending data to client
    s_sec_ack_pkt.data.data.data = b'\x43' * (payload_len - 1) + b'\x59'
    s_sec_ack_pkt.data.len += payload_len
    s_sec_ack_pkt = tcp_fix_checksum(s_sec_ack_pkt)
    tcpsession._process(s_sec_ack_pkt.pack())
    assert len(sessions[1]) == 7
    last_s_tcp_pkt = dpkt.ethernet.Ethernet(sessions[1][tcpsession._s_prev_pkt_ind][1])
    assert (hash_digest(last_s_tcp_pkt.data.data.data) ==
            hash_digest(b'\x43' * (payload_len - 1) + b'\x59'))

    # test partial retransmission from server
    partial_retransmit_size = 5
    s_sec_ack_pkt.data.data.seq += (payload_len - partial_retransmit_size)
    s_sec_ack_pkt.data.data.data = b'\x5a' * (partial_retransmit_size + 1) + b'\x44' * (payload_len - 1)
    s_sec_ack_pkt.data.len += (partial_retransmit_size + payload_len)
    s_sec_ack_pkt = tcp_fix_checksum(s_sec_ack_pkt)
    tcpsession._process(s_sec_ack_pkt.pack())
    assert len(sessions[1]) == 8
    last_s_tcp_pkt = dpkt.ethernet.Ethernet(sessions[1][tcpsession._s_prev_pkt_ind][1])
    assert (hash_digest(last_s_tcp_pkt.data.data.data) ==
            hash_digest(b'\x5a' + b'\x44' * (payload_len - 1)))
    # test is data sent by server is equals to next packets seq number adjusted with partial retransmitted size
    assert last_ack_by_client + payload_len == s_sec_ack_pkt.data.data.seq + partial_retransmit_size
    # test if data send by server is properly received by client and it has adjusted it's sequence number
    # and next sequence number
    assert last_ack_by_client + 2 * payload_len == (last_s_tcp_pkt.data.data.seq +
                                                    (last_s_tcp_pkt.data.len - last_s_tcp_pkt.data.hl * 4 -
                                                     last_s_tcp_pkt.data.data.off * 4))
    # test that checksum of IP layer and TCP layer is modified correctly
    s_sec_ack_pkt.data.len -= partial_retransmit_size
    s_sec_ack_pkt.data.data.seq += partial_retransmit_size
    s_sec_ack_pkt.data.data.data = b'\x5a' + b'\x44' * (payload_len - 1)
    s_sec_ack_pkt = tcp_fix_checksum(s_sec_ack_pkt)
    assert last_s_tcp_pkt.data.sum == s_sec_ack_pkt.data.sum
    assert last_s_tcp_pkt.data.data.sum == s_sec_ack_pkt.data.data.sum
    with open("data/test_slide_window.pcap", "wb") as fp:
        dpkt_writer = dpkt.pcap.Writer(fp)
        for session_num in sessions.keys():
            for ts, pkt in sessions[session_num]:
                dpkt_writer.writepkt(pkt)


def test_tcp_3_way_conn_termination_c_init(debug=False):
    tcpsession = tcp_hand_shake()
    if debug:
        tcpsession.set_print_debug_info()
    payload = b"hello"
    c_sec_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_sec_ack_pkt.data.data.data = payload
    c_sec_ack_pkt.data.len += len(payload)
    c_sec_ack_pkt = tcp_fix_checksum(c_sec_ack_pkt)
    tcpsession._process(c_sec_ack_pkt.pack())

    c_fin_pkt = copy.deepcopy(t_c_fin_pkt)
    c_fin_pkt.data.data.seq = c_sec_ack_pkt.data.data.seq + len(payload)
    c_fin_pkt.data.data.ack = c_sec_ack_pkt.data.data.ack
    c_fin_pkt = tcp_fix_checksum(c_fin_pkt)
    tcpsession._process(c_fin_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 5
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_1 and s_state == TCPState.ESTABLISHED

    # ack the clients data
    # s_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    # s_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    # s_ack_pkt.data.data.ack = c_sec_ack_pkt.data.data.seq + len(payload)
    # s_ack_pkt = tcp_checksum_fix(s_ack_pkt)
    # tcpsession._process(s_ack_pkt.pack())
    # assert len(sessions[1]) == 6
    # c_state, s_state = tcpsession.getstates()
    # assert c_state == TCPState.FIN_WAIT_1 and s_state == TCPState.ESTABLISHED
    return tcpsession, 5, tcpsession.get_states()


def test_tcp_3_way_conn_termination_s_init_without_data():
    tcpsession = tcp_hand_shake()
    payload = b"Hello"
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.data = payload
    c_ack_pkt.data.len += len(payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    s_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    s_ack_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + len(payload)
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 5
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED

    s_fin_pkt = copy.deepcopy(t_s_fin_pkt)
    s_fin_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_fin_pkt.data.data.ack = last_c_pkt.data.data.seq + len(payload)
    s_fin_pkt = tcp_fix_checksum(s_fin_pkt)
    tcpsession._process(s_fin_pkt.pack())
    assert len(sessions[1]) == 6
    c_state, s_state = tcpsession.get_states()
    assert s_state == TCPState.FIN_WAIT_1 and c_state == TCPState.ESTABLISHED
    return tcpsession, 6


def test_tcp_3_way_conn_termination_s_init():
    tcpsession = tcp_hand_shake()
    payload = b"Hello"
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.data = payload
    c_ack_pkt.data.len += len(payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_payload = b"Hi client!"
    s_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    s_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    s_ack_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + len(payload)
    s_ack_pkt.data.data.data = s_payload
    s_ack_pkt.data.len += len(s_payload)
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 5
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_fin_pkt = copy.deepcopy(t_s_fin_pkt)
    s_fin_pkt.data.data.seq = last_s_pkt.data.data.seq + len(s_payload)
    s_fin_pkt.data.data.ack = last_c_pkt.data.data.seq + len(payload)
    s_fin_pkt = tcp_fix_checksum(s_fin_pkt)
    tcpsession._process(s_fin_pkt.pack())
    assert len(sessions[1]) == 6
    c_state, s_state = tcpsession.get_states()
    assert s_state == TCPState.FIN_WAIT_1 and c_state == TCPState.ESTABLISHED
    return tcpsession, 6


def test_tcp_3_way_conn_termination_s_completion():
    tcpsession, pkt_count = test_tcp_3_way_conn_termination_s_init()

    # ACK the servers data
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack, last_s_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1,
                       TCPState.ESTABLISHED, TCPState.FIN_WAIT_1)

    # ACK the server's FIN and send FIN with it
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_fin_ack = copy.deepcopy(t_c_sec_ack_pkt)
    c_fin_ack.data.data.flags |= dpkt.tcp.TH_FIN
    c_fin_ack.data.data.ack = last_s_pkt.data.data.seq + 1
    c_fin_ack.data.data.seq = last_s_pkt.data.data.ack
    c_fin_ack = tcp_fix_checksum(c_fin_ack)
    tcpsession._process(c_fin_ack.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == pkt_count + 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.LAST_ACK and s_state == TCPState.FIN_WAIT_2

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_final_ack = copy.deepcopy(t_s_sec_ack_pkt)
    s_final_ack.data.data.seq = last_c_pkt.data.data.ack
    s_final_ack.data.data.ack = last_c_pkt.data.data.seq + 1
    s_final_ack = tcp_fix_checksum(s_final_ack)
    tcpsession._process(s_final_ack.pack())
    assert len(sessions[1]) == pkt_count + 3
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_4_way_conn_termination_s_completion_of_init_without_data():
    tcpsession, pkt_count = test_tcp_3_way_conn_termination_s_init_without_data()

    # Send some more data
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    payload = b"more data..."
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack, last_s_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK, payload)
    tcpsession._process(c_ack_pkt.pack())
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.ESTABLISHED, TCPState.FIN_WAIT_1)

    # ACK the server FIN
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack + len(payload),
                                  last_s_pkt.data.data.seq + 1,
                                  dpkt.tcp.TH_ACK, payload)
    tcpsession._process(c_ack_pkt.pack())
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 2, TCPState.CLOSE_WAIT, TCPState.FIN_WAIT_2)

    # FIN from client
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq + len(payload),
                                  last_c_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 3, TCPState.LAST_ACK, TCPState.FIN_WAIT_2)

    # ACK from server for additional data
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack, last_c_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 4, TCPState.LAST_ACK, TCPState.FIN_WAIT_2)

    # ACK the client FIN packet
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack, last_c_pkt.data.data.seq + 1,
                                  dpkt.tcp.TH_ACK)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 5, TCPState.CLOSED, TCPState.CLOSED)


def test_tcp_3_way_conn_termination_completion():
    tcpsession, session_pkt_count, session_state = test_tcp_3_way_conn_termination_c_init()
    sessions = tcpsession.get_sessions()
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())

    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, t_s_sec_ack_pkt.data.data.seq, last_c_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, session_pkt_count + 1, TCPState.FIN_WAIT_1,
                       TCPState.ESTABLISHED)

    # ACK the client FIN request and send FIN request, this is three way TCP termination
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_fin_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    s_fin_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN
    s_fin_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + 1
    s_fin_ack_pkt = tcp_fix_checksum(s_fin_ack_pkt)
    tcpsession._process(s_fin_ack_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.LAST_ACK

    # client ack the server FIN request
    c_final_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    c_final_ack_pkt.data.data.flag = dpkt.tcp.TH_ACK
    c_final_ack_pkt.data.data.ack = s_fin_ack_pkt.data.data.seq + 1
    c_final_ack_pkt.data.data.seq = s_fin_ack_pkt.data.data.ack
    c_final_ack_pkt = tcp_fix_checksum(c_final_ack_pkt)
    tcpsession._process(c_final_ack_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 3
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_4_way_active_side_termination(debug=False):
    tcpsession, session_pkt_count, session_state = test_tcp_3_way_conn_termination_c_init(debug)
    # ACK the client data first
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())

    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, t_s_sec_ack_pkt.data.data.seq, last_c_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, session_pkt_count + 1, TCPState.FIN_WAIT_1,
                       TCPState.ESTABLISHED)

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    sessions = tcpsession.get_sessions()

    # so far client data has been acknowledged
    # send some data to client
    s_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    s_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    s_ack_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_payload = b"Hi!"
    s_ack_pkt.data.data.data = s_payload
    s_ack_pkt.data.data.ack = last_s_pkt.data.data.ack
    s_ack_pkt.data.len += len(s_payload)
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_1 and s_state == TCPState.ESTABLISHED
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())

    # ACK the client FIN
    """
    s_ack_client_fin_pkt = copy.deepcopy(s_ack_pkt)
    s_ack_client_fin_pkt.data.data.ack = last_c_pkt.data.data.seq + 1
    s_ack_client_fin_pkt.data.data.seq += len(s_payload)
    s_ack_client_fin_pkt.data.len -= len(s_payload)
    s_ack_client_fin_pkt = tcp_checksum_fix(s_ack_client_fin_pkt)
    tcpsession._process(s_ack_client_fin_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 3
    c_state, s_state = tcpsession.getstates()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.CLOSE_WAIT
    """
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_client_fin_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt,
                                             last_c_pkt.data.data.ack + len(s_payload),
                                             last_c_pkt.data.data.seq + 1)
    verify_tcp_session(tcpsession, s_ack_client_fin_pkt, 1, session_pkt_count + 3,
                       TCPState.FIN_WAIT_2, TCPState.CLOSE_WAIT)

    # send more data from server to client
    s_ack_pkt = copy.deepcopy(s_ack_client_fin_pkt)
    s_payload = b"Good things come to those who wait."
    s_ack_pkt.data.data.data = s_payload
    s_ack_pkt.data.len += len(s_payload)
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 4
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.CLOSE_WAIT

    # client ACK server data in FIN_WAIT2 state
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = last_c_pkt
    c_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = (last_s_pkt.data.data.seq +
                               (last_s_pkt.data.len - 4 * last_s_pkt.data.hl - 4 * last_s_pkt.data.data.off))
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    assert len(sessions[1]) == session_pkt_count + 5
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.CLOSE_WAIT
    return tcpsession, session_pkt_count + 5, tcpsession.get_states()


def test_tcp_4_way_active_side_s_termination():
    tcpsession, pkt_count = test_tcp_3_way_conn_termination_s_init()

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    # send some data and ACK the servers data
    payload = b"Some more data from client..."
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack, last_s_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK, payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.FIN_WAIT_1)

    # ACK the servers FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq + len(payload),
                                  last_s_pkt.data.data.seq + 1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 2, TCPState.CLOSE_WAIT,
                       TCPState.FIN_WAIT_2)
    return tcpsession, pkt_count + 2


def test_tcp_4_way_passive_side_termination():
    tcpsession, session_pkt_count, session_state = test_tcp_4_way_active_side_termination()

    # server sends FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_fin_pkt = last_s_pkt
    s_fin_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_fin_pkt.data.data.flags = dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK
    s_fin_pkt.data.len -= (last_s_pkt.data.len -
                           4 * last_s_pkt.data.hl - 4 * last_s_pkt.data.data.off)
    s_fin_pkt.data.data.data = b""
    s_fin_pkt = tcp_fix_checksum(s_fin_pkt)

    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_fin_pkt, tcpsession.get_session_count(), session_pkt_count,
                       TCPState.FIN_WAIT_2, TCPState.CLOSE_WAIT)
    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, 1)
    tcpsession._process(s_fin_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == session_pkt_count + 1
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.LAST_ACK

    # client ACKs the server
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_final_fin = last_c_pkt
    c_ack_final_fin.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_final_fin.data.data.seq = last_s_pkt.data.data.ack
    c_ack_final_fin = tcp_fix_checksum(c_ack_final_fin)
    tcpsession._process(c_ack_final_fin.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == session_pkt_count + 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_4_way_passive_side_s_termination():
    tcpsession, pkt_count = test_tcp_4_way_active_side_s_termination()
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    # send some more data after ACKing the server's FIN
    payload = b"Would be pretty cool, if you would handle this server."
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq,
                                  last_c_pkt.data.data.ack, payload=payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.CLOSE_WAIT,
                       TCPState.FIN_WAIT_2)

    # Server ACK the sent data
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + len(payload))
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2,
                       TCPState.CLOSE_WAIT, TCPState.FIN_WAIT_2)

    # send FIN to server
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack,
                                  last_s_pkt.data.data.seq + 1, dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN)

    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 2, TCPState.CLOSE_WAIT,
                       TCPState.FIN_WAIT_2)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 3, TCPState.LAST_ACK,
                       TCPState.FIN_WAIT_2)

    # Server ACK the FIN
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + 1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 4,
                       TCPState.CLOSED, TCPState.CLOSED)


def test_tcp_4_way_passive_side_piggyback_termination(debug=False):
    tcpsession, session_pkt_count, session_state = test_tcp_4_way_active_side_termination(debug)

    # server sends FIN piggy-backed with data
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_fin_pkt = last_s_pkt
    s_payload = b"Piggybacked FIN"
    """
    s_fin_pkt.data.data.data = s_payload
    s_fin_pkt.data.data.flags = dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK
    s_fin_pkt.data.data.seq = last_s_pkt.data.data.ack
    # commenting below line should not make test cases fail
    # s_fin_pkt.data.data.ack = last_c_pkt.data.data.seq
    s_fin_pkt.data.len -= (last_s_pkt.data.len -
                           4*last_s_pkt.data.hl - 4*last_s_pkt.data.data.off)
    s_fin_pkt.data.len += len(s_payload)
    s_fin_pkt = tcp_checksum_fix(s_fin_pkt)
    tcpsession._process(s_fin_pkt.pack())
    sessions = tcpsession.getsessions()
    assert len(sessions[1]) == session_pkt_count + 1
    c_state, s_state = tcpsession.getstates()
    assert c_state == TCPState.FIN_WAIT_2 and s_state == TCPState.LAST_ACK
    """
    s_fin_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack, last_s_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN, s_payload)
    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, 0 - len(s_payload) - 1)
    verify_tcp_session(tcpsession, s_fin_pkt, 1, session_pkt_count, TCPState.FIN_WAIT_2,
                       TCPState.CLOSE_WAIT)
    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, len(s_payload) + 1)
    verify_tcp_session(tcpsession, s_fin_pkt, 1, session_pkt_count + 1, TCPState.FIN_WAIT_2,
                       TCPState.LAST_ACK)

    # client ACKs the FIN and data send by server
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = last_c_pkt
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + (last_s_pkt.data.len -
                                                          4 * last_s_pkt.data.hl - 4 * last_s_pkt.data.data.off)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == session_pkt_count + 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_4_way_passive_side_s_piggyback_termination():
    tcpsession, pkt_count = test_tcp_4_way_active_side_s_termination()
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    # send some more data after ACKing the server's FIN
    payload = b"Would be pretty cool, if you would handle this server."
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq,
                                  last_c_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN,
                                  payload=payload)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, 0 - len(payload) - 1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count, TCPState.CLOSE_WAIT,
                       TCPState.FIN_WAIT_2)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, 1 + len(payload))
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.LAST_ACK,
                       TCPState.FIN_WAIT_2)

    # Server ACK the sent data and FIN with same packet
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + len(payload))
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2,
                       TCPState.CLOSED, TCPState.CLOSED)


def test_tcp_4_way_closing_state_termination():
    tcpsession, pkt_count, session_state = test_tcp_3_way_conn_termination_c_init()
    sessions = tcpsession.get_sessions()
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    # send FIN to client piggybacked with ACK of data
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack, last_c_pkt.data.data.seq,
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count, TCPState.FIN_WAIT_1,
                       TCPState.ESTABLISHED)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 1, TCPState.CLOSING,
                       TCPState.CLOSING)
    # client ACKs the servers FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq, last_s_pkt.data.data.seq + 1)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.CLOSING,
                       TCPState.CLOSING)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_ack_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 2, TCPState.CLOSING,
                       TCPState.CLOSED)
    # server ACKs the client FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + 1)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2,
                       TCPState.CLOSING, TCPState.CLOSED)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 3,
                       TCPState.CLOSED, TCPState.CLOSED)


def test_tcp_4_way_closing_state_s_termination():
    tcpsession, pkt_count = test_tcp_3_way_conn_termination_s_init()
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())

    c_fin_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack,
                                      last_s_pkt.data.data.seq, dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN)
    verify_tcp_session(tcpsession, c_fin_ack_pkt, 1, pkt_count + 1,
                       TCPState.CLOSING, TCPState.CLOSING)
    # ACK the server FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack,
                                  last_s_pkt.data.data.seq + 1)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 2,
                       TCPState.CLOSING, TCPState.CLOSED)
    # server ACK's the client's FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + 1)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 3,
                       TCPState.CLOSED, TCPState.CLOSED)


def test_tcp_reset_termination_after_data_transfer():
    tcpsession = tcp_hand_shake()
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_payload = b"Test data"
    c_ack_pkt.data.data.data = c_payload
    c_ack_pkt.data.len += len(c_payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 4

    # send RST to server
    c_ack_pkt.data.data.seq += len(c_payload)
    c_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK | dpkt.tcp.TH_RST
    c_ack_pkt.data.len -= len(c_payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 5
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_reset_termination_from_other_side():
    tcpsession = tcp_hand_shake()
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_payload = b"Test data"
    c_ack_pkt.data.data.data = c_payload
    c_ack_pkt.data.len += len(c_payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 4

    # server sends data
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = copy.deepcopy(t_s_sec_ack_pkt)
    s_ack_pkt.data.data.seq = last_c_pkt.data.data.ack
    s_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + (last_c_pkt.data.len -
                                                          last_c_pkt.data.hl * 4 - last_c_pkt.data.data.off * 4)
    s_payload = b"Test server payload"
    s_ack_pkt.data.data.data = s_payload
    s_ack_pkt.data.len += len(s_payload)
    s_ack_pkt.data.flags = dpkt.tcp.TH_ACK
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 5

    # server sends RST
    s_ack_pkt.data.data.data = b""
    s_ack_pkt.data.len -= len(s_payload)
    s_ack_pkt.data.data.seq += len(s_payload)
    s_ack_pkt.data.data.flags = dpkt.tcp.TH_RST
    s_ack_pkt = tcp_fix_checksum(s_ack_pkt)
    tcpsession._process(s_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 6)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_reset_termination_first_pkt():
    c_syn_rst_pkt = copy.deepcopy(t_first_syn_pkt)
    c_syn_rst_pkt.data.data.flags = dpkt.tcp.TH_SYN | dpkt.tcp.TH_RST
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_rst_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 1)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_reset_termination_other_side_first_pkt():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    s_rst_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_rst_pkt.data.data.flags = dpkt.tcp.TH_RST
    tcpsession._process(s_rst_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 2)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_no_syn_ack_in_handshake():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.flags = 0
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 2)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_no_syn_only_ack_in_handshake():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.flags = dpkt.tcp.TH_ACK
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 2)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_no_ack_only_syn_in_handshake():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.flags = dpkt.tcp.TH_SYN
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 2)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_no_syn_in_conn_init():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    c_syn_pkt.data.data.flags = 0
    c_syn_pkt = tcp_fix_checksum(c_syn_pkt)
    tcpsession._process(c_syn_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions.keys()) == 0)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.LISTENING

    # send another packet without SYN flag
    c_syn_pkt.data.data.flags = 0x029
    c_syn_pkt = tcp_fix_checksum(c_syn_pkt)
    tcpsession._process(c_syn_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions.keys()) == 0
    #assert len(sessions[1]) == 0 and len(sessions[2]) == 0
    assert c_state == TCPState.CLOSED and s_state == TCPState.LISTENING


def test_tcp_syn_after_handshake():
    tcpsession = tcp_hand_shake()
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.flags = 0x01A
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 4)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_tcp_twice_syn_in_handshake():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 2)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.SYN_SENT and s_state == TCPState.SYN_RECEIVED

    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.flags = 0x01A
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 3)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.CLOSED and s_state == TCPState.CLOSED


def test_inc_tcp_seq_number():
    seq_num = 0xFFFFFFF0
    inc_by = 0x0F

    new_seq_num = inc_tcp_seq_number(seq_num, inc_by)
    assert new_seq_num == seq_num + inc_by
    assert inc_tcp_seq_number(new_seq_num, 5) == 4
    assert inc_tcp_seq_number(new_seq_num, 1) == 0
    assert inc_tcp_seq_number(1, 0xFFFFFFFF) == 0
    assert inc_tcp_seq_number(1, 0x1FFFFFFFF) == 0
    assert inc_tcp_seq_number(0, 0xFFFFFFFF) == 0xFFFFFFFF
    assert inc_tcp_seq_number(-1, 12341) is None
    assert inc_tcp_seq_number(23, -32342) == SEQ_NUM_MOD_CONST - 32319
    assert inc_tcp_seq_number(0, -1) == MAX_SEQ_NUM
    assert inc_tcp_seq_number(0, 0 - 0xFFFFFFFF) == 1
    assert inc_tcp_seq_number(1, -1) == 0


def test_tcp_seq_number_in_window():
    start_seq_number = 0xFFFFFFF0
    seq_number = 0xFFFFFFFF
    assert tcp_seq_number_in_window(start_seq_number, seq_number)
    assert tcp_seq_number_in_window(start_seq_number, 0)
    assert tcp_seq_number_in_window(start_seq_number, inc_tcp_seq_number(start_seq_number, MAX_TCP_WINDOW_SIZE))
    assert tcp_seq_number_in_window(start_seq_number, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS) is False
    assert tcp_seq_number_in_window(start_seq_number, start_seq_number - 1) is False
    assert tcp_seq_number_in_window(0, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS - 1)
    assert tcp_seq_number_in_window(0, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS) is False
    assert tcp_seq_number_in_window(start_seq_number,
                                    inc_tcp_seq_number(start_seq_number, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS) - 1)
    assert tcp_seq_number_in_window(start_seq_number,
                                    inc_tcp_seq_number(start_seq_number, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS)
                                    ) is False
    assert tcp_seq_number_in_window(start_seq_number, seq_number, MAX_TCP_WINDOW_SIZE_WITH_OPTIONS + 1) is None
    assert tcp_seq_number_in_window(-1, seq_number) is None


def test_seq_numbers_diff():
    start_seq = 0xFFFFFFF0
    diff = 5
    end_seq = start_seq + diff
    assert seq_numbers_diff(start_seq, end_seq) == diff
    diff = 0x0F
    end_seq = start_seq + diff
    assert seq_numbers_diff(start_seq, end_seq) == diff
    diff = 0x10
    end_seq = start_seq + diff
    assert seq_numbers_diff(start_seq, end_seq) == diff
    diff = 0xFFFFFFFF
    end_seq = start_seq + diff
    assert seq_numbers_diff(start_seq, end_seq) == diff
    assert seq_numbers_diff(-1, -1) is None
    assert seq_numbers_diff(-1, 123) is None
    assert seq_numbers_diff(12, -1) is None


def test_tcp_wrap_around_client_seq_number():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)

    init_seq_num = 0xFFFFFFF0
    c_syn_pkt.data.data.seq = init_seq_num
    c_syn_pkt = tcp_fix_checksum(c_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + 1
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())

    # seq number with zero will be tested later
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    payload = b'\x90' * (MAX_SEQ_NUM + 1 - init_seq_num)
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt.data.data.data = payload
    c_ack_pkt.data.len += len(payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 4)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED
    assert tcpsession._s_rcv_next == inc_tcp_seq_number(last_s_pkt.data.data.ack, len(payload))


def test_tcp_wrap_around_client_exact_zero_seq_number():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)

    init_seq_num = 0xFFFFFFF0
    c_syn_pkt.data.data.seq = init_seq_num
    c_syn_pkt = tcp_fix_checksum(c_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.ack = last_c_pkt.data.data.seq + 1
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    payload = b'\x90' * (MAX_SEQ_NUM - last_s_pkt.data.data.ack)
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt.data.data.data = payload
    c_ack_pkt.data.len += len(payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert (len(sessions[1]) == 4)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED
    assert tcpsession._s_rcv_next == inc_tcp_seq_number(last_s_pkt.data.data.ack, len(payload))

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    #payload = b'\x90' * tcpsession.get_server_mss()
    payload = b'\x90' * TCP_MSS_DEFAULT
    c_ack_pkt = copy.deepcopy(t_c_sec_ack_pkt)
    c_ack_pkt.data.data.seq = tcpsession._s_rcv_next
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt.data.data.data = payload
    c_ack_pkt.data.len += len(payload)
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    assert (len(sessions[1]) == 5)
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED
    assert tcpsession._s_rcv_next == inc_tcp_seq_number(c_ack_pkt.data.data.seq, len(payload))


def test_tcp_wrap_around_client_init_seq_number_ffffffff():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    init_seq_num = 0xFFFFFFFF
    c_syn_pkt.data.data.seq = init_seq_num
    c_syn_pkt = tcp_fix_checksum(c_syn_pkt)
    tcpsession = TCPSession("", sip, dip, sport, dport)
    tcpsession._process(c_syn_pkt.pack())

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    # last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt.data.data.ack = inc_tcp_seq_number(last_c_pkt.data.data.seq, 1)
    s_syn_ack_pkt = tcp_fix_checksum(s_syn_ack_pkt)
    tcpsession._process(s_syn_ack_pkt.pack())
    sessions = tcpsession.get_sessions()
    assert len(sessions[1]) == 2
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.SYN_SENT and s_state == TCPState.SYN_RECEIVED
    assert tcpsession._s_rcv_next == 0

    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    c_ack_pkt.data.data.seq = last_s_pkt.data.data.ack
    c_ack_pkt.data.data.ack = last_s_pkt.data.data.seq + 1
    c_ack_pkt = tcp_fix_checksum(c_ack_pkt)
    tcpsession._process(c_ack_pkt.pack())
    assert len(sessions[1]) == 3
    c_state, s_state = tcpsession.get_states()
    assert c_state == TCPState.ESTABLISHED and s_state == TCPState.ESTABLISHED


def test_tcp_checksum_calculation():
    src = sip
    dst = dip
    p = p_tcp
    payload_with_fin_flag = b'\xdc\x0c\x00P\xde\xad\xbe\xf5\xbe\xef\xde\xaeP\x11\xff\xff\x8f)\x00\x00'

    payload_without_fin_with_inc_ack = b'\xdc\x0c\x00P\xde\xad\xbe\xf5\xbe\xef\xde\xafP\x10\xff\xff\x8f)\x00\x00'
    assert (tcp_checksum_calc(src, dst, p, payload_without_fin_with_inc_ack) ==
            tcp_checksum_calc(src, dst, p, payload_with_fin_flag))
    assert tcp_shasum_calc(src, dst, p, "payload") == hash_digest(struct.pack(">4s4sxBH",
                                                                              src, dst,
                                                                              p, len("payload")) + b'payload')


def test_tcp_rcv_next():
    tcpsession = TCPSession("", sip, dip, sport, dport)

    verify_tcp_session(tcpsession, None, 0, 0, TCPState.CLOSED, TCPState.LISTENING,
                       0, 0)
    verify_tcp_session(tcpsession, t_first_syn_pkt, 1, 1, TCPState.SYN_SENT, TCPState.SYN_RECEIVED,
                       0, 0)
    verify_tcp_session(tcpsession, t_syn_ack_pkt, 1, 2, TCPState.SYN_SENT, TCPState.SYN_RECEIVED,
                       0, c_start_seq_num + 1)
    verify_tcp_session(tcpsession, t_c_sec_ack_pkt, 1, 3, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       s_start_seq_num + 1, c_start_seq_num + 1)
    # Handshake complete
    payload = b"Hello!"
    payload_len = len(payload)
    sessions = tcpsession.get_sessions()
    pkt_count = len(sessions[1])
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_expected_next_rcv = s_start_seq_num + 1
    s_expected_next_rcv = c_start_seq_num + 1
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack, last_c_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK, payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv, s_expected_next_rcv + payload_len,
                       total_c_data_len=len(payload), total_s_data_len=0)
    s_payload = b"Hi, client!!"
    s_payload_len = len(s_payload)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_expected_next_rcv += payload_len
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + payload_len, dpkt.tcp.TH_ACK,
                                  s_payload)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv + s_payload_len,
                       s_expected_next_rcv, total_c_data_len=len(payload), total_s_data_len=len(s_payload))


def test_tcp_out_of_order_pkts(debug=False):
    tcpsession = tcp_hand_shake(debug)
    sessions = tcpsession.get_sessions()
    pkt_count = len(sessions[1])
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_expected_next_rcv = tcpsession.get_client_next_rcv()
    s_expected_next_rcv = tcpsession.get_server_next_rcv()
    prev_payload = b"This is in order data"
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_s_pkt.data.data.ack, last_c_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK, prev_payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv,
                       s_expected_next_rcv + len(prev_payload))
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_expected_next_rcv = tcpsession.get_client_next_rcv()
    s_expected_next_rcv = tcpsession.get_server_next_rcv()
    payload = b"This is payload of delayed packet"
    out_of_order_payload = b"This is an out of order packet, delivered earlier than it should be"
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt,
                                  last_c_pkt.data.data.seq + len(prev_payload) + len(payload),
                                  last_c_pkt.data.data.ack, dpkt.tcp.TH_ACK, out_of_order_payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv,
                       s_expected_next_rcv)
    out_of_order_q = tcpsession.get_server_out_of_order_pkt_queue()
    assert len(out_of_order_q) == 1
    c_ack_pkt = duplicate_tcp_pkt(t_c_sec_ack_pkt, last_c_pkt.data.data.seq + len(prev_payload),
                                  last_c_pkt.data.data.ack, dpkt.tcp.TH_ACK, payload)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, pkt_count + 3, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv,
                       s_expected_next_rcv + len(payload) + len(out_of_order_payload))

    # Test the logic on server side
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_expected_next_rcv = tcpsession.get_client_next_rcv()
    s_expected_next_rcv = tcpsession.get_server_next_rcv()
    s_prev_payload = b"in order data from server"
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, last_c_pkt.data.data.ack, s_expected_next_rcv,
                                  dpkt.tcp.TH_ACK, s_prev_payload)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 4, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv + len(s_prev_payload),
                       s_expected_next_rcv)
    s_payload = b"paylod of delayed pkt from server"
    s_out_of_order_payload = b"out of order packet's payload"
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_expected_next_rcv = tcpsession.get_client_next_rcv()
    s_expected_next_rcv = tcpsession.get_server_next_rcv()
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, c_expected_next_rcv + len(s_payload),
                                  last_s_pkt.data.data.ack, dpkt.tcp.TH_ACK, s_out_of_order_payload)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 4, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, c_expected_next_rcv,
                       s_expected_next_rcv)
    assert len(tcpsession.get_client_out_of_order_pkt_queue()) == 1
    s_ack_pkt = duplicate_tcp_pkt(t_s_sec_ack_pkt, c_expected_next_rcv, last_s_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK, s_payload, )
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 6, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED,
                       c_expected_next_rcv + len(s_payload) + len(s_out_of_order_payload),
                       s_expected_next_rcv)
    assert len(tcpsession.get_client_out_of_order_pkt_queue()) == 0


def test_tcp_opts_tuple_list_to_dict():
    buf = b'\x02\x04\x23\x00\x01\x01\x04\x02'
    opts = dpkt.tcp.parse_opts(buf)
    opts_dict = tcp_opts_tuple_list_to_dict(opts)
    assert opts_dict == {
        dpkt.tcp.TCP_OPT_MSS: b'\x23\x00',
        dpkt.tcp.TCP_OPT_NOP: b'',
        dpkt.tcp.TCP_OPT_SACKOK: b''
    }

    buf = b'\x01\x01\x05\x0a\x37\xf8\x19\x70\x37\xf8\x29\x78'
    opts = dpkt.tcp.parse_opts(buf)
    opts_dict = tcp_opts_tuple_list_to_dict(opts)
    assert opts_dict == {
        dpkt.tcp.TCP_OPT_NOP: b'',
        dpkt.tcp.TCP_OPT_SACK: b'\x37\xf8\x19\x70\x37\xf8\x29\x78'
    }

    # test a zero-length option
    buf = b'\x02\x00\x01'
    opts = dpkt.tcp.parse_opts(buf)
    opts_dict = tcp_opts_tuple_list_to_dict(opts)
    assert opts_dict == {
        dpkt.tcp.TCP_OPT_MSS: b'',
        dpkt.tcp.TCP_OPT_NOP: b''
    }


def test_tcp_option_mss_payload():
    assert tcp_option_mss_paylod(1460) == TCP_MSS_OPTION_PREFIX + struct.pack(">H", 1460)
    assert tcp_option_mss_paylod(-1) == b''
    assert tcp_option_mss_paylod(0x10000) == b''
    assert tcp_option_mss_paylod(0xFFFF) == TCP_MSS_OPTION_PREFIX + b'\xFF\xFF'
    assert tcp_option_mss_paylod(0) == TCP_MSS_OPTION_PREFIX + b"\x00\x00"
    assert tcp_option_mss_paylod(9000) == TCP_MSS_OPTION_PREFIX + struct.pack(">H", 9000)


def test_tcp_option_window_scale_payload():
    assert tcp_option_window_scale_payload(8) == TCP_WINDOW_SCALE_OPTION_PREFIX + b'\x08'
    assert tcp_option_window_scale_payload(14) == TCP_WINDOW_SCALE_OPTION_PREFIX + b'\x0E'
    assert tcp_option_window_scale_payload(15) == b''
    assert tcp_option_window_scale_payload(0) == TCP_WINDOW_SCALE_OPTION_PREFIX + b'\x00'
    assert tcp_option_window_scale_payload(-1) == b''
    assert tcp_option_window_scale_payload(1) == TCP_WINDOW_SCALE_OPTION_PREFIX + b'\x01'


def test_tcp_options_payload():
    window_scale = 8
    options = [tcp_option_mss_paylod(TCP_MSS_DEFAULT), tcp_option_window_scale_payload(window_scale),
               TCP_SELECTIVE_ACK_PERMITTED_OPTION, b'\x65\x02']
    options_byte = tcp_option_payload_creation(options)
    expected_byte = (TCP_MSS_OPTION_PREFIX + TCP_MSS_DEFAULT_BYTES +
                     TCP_WINDOW_SCALE_OPTION_PREFIX + bytes([window_scale]) +
                     TCP_SELECTIVE_ACK_PERMITTED_OPTION + b'\x65\x02' +
                     TCP_NOP_OPTION_PAYLOAD)
                     #TCP_NOP_OPTION_PAYLOAD +
                     #TCP_NOP_OPTION_PAYLOAD +)
    assert options_byte == expected_byte
    options = [tcp_option_time_stamp_payload(-1, 0)]
    assert options == [b'']
    assert craft_tcp_packet_with_options(None, options) == b''
    assert get_tcp_packet_payload_len_with_options(None) is None
    assert get_tcp_packet_payload_len(None) is None


def test_tcp_hand_shake_with_tcp_options(debug=False, c_win_scale=5, s_win_scale=6, c_mss=1460, s_mss=1460):
    tcpsession = TCPSession("", sip, dip, sport, dport)
    if debug:
        tcpsession.set_print_debug_info()
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    option_list = [tcp_option_mss_paylod(c_mss),
                   tcp_option_window_scale_payload(c_win_scale),
                   tcp_option_time_stamp_payload(c_start_timestamp_val, 0),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    options_payload = tcp_option_payload_creation(option_list)
    c_syn_pkt.data.data.opts = options_payload
    c_syn_pkt.data.data.off = 5 + int(len(options_payload) / 4)
    verify_tcp_session(tcpsession, c_syn_pkt, 1, 1, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)
    assert tcpsession.get_client_window_scale_factor() == c_win_scale

    s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    option_list = [tcp_option_window_scale_payload(s_win_scale),
                   tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    options_payload = tcp_option_payload_creation(option_list)
    s_syn_ack_pkt.data.data.opts = options_payload
    s_syn_ack_pkt.data.data.off = 5 + int(len(options_payload) / 4)
    verify_tcp_session(tcpsession, s_syn_ack_pkt, 1, 2, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)

    c_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    options_list = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    options_payload = tcp_option_payload_creation(option_list)
    c_ack_pkt.data.data.opts = options_payload
    c_ack_pkt.data.data.off = 5 + int(len(options_payload) / 4)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 3, TCPState.ESTABLISHED, TCPState.ESTABLISHED)

    assert tcpsession.get_client_window_scale_factor() == c_win_scale
    assert tcpsession.get_server_window_scale_factor() == s_win_scale
    assert tcpsession.get_client_mss() == c_mss
    assert tcpsession.get_server_mss() == -1
    return tcpsession


def test_tcp_with_options_handshake(debug=False, c_start_seq=-1, s_start_seq=-1) -> (TCPSession, int, int, int):
    """

    :param debug:
    :param c_start_seq:
    :param s_start_seq:
    :return: TCPSession
    """
    tcpsession = TCPSession("", sip, dip, sport, dport)
    if debug:
        tcpsession.set_print_debug_info()
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    c_syn_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    c_win_scale = 7
    # actual client rwnd is of 128 bytes
    actual_client_rwnd = c_syn_pkt.data.data.win << c_win_scale
    c_mss = 1460
    option_list = [tcp_option_mss_paylod(c_mss),
                   tcp_option_window_scale_payload(c_win_scale),
                   tcp_option_time_stamp_payload(c_start_timestamp_val, 0),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    if not c_start_seq < 0:
        c_syn_pkt.data.data.seq = c_start_seq
    c_syn_pkt = craft_tcp_packet_with_options(c_syn_pkt, option_list)
    verify_tcp_session(tcpsession, c_syn_pkt, 1, 1, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)
    assert tcpsession.get_client_scaled_window_size() == actual_client_rwnd
    # s_syn_ack_pkt = copy.deepcopy(t_syn_ack_pkt)
    s_syn_ack_pkt = duplicate_tcp_pkt(t_syn_ack_pkt, t_syn_ack_pkt.data.data.seq,
                                      inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1),
                                      dpkt.tcp.TH_ACK | dpkt.tcp.TH_SYN)
    s_syn_ack_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    s_win_scale = 6
    # actual server rwnd is of 64 bytes
    actual_server_rwnd = s_syn_ack_pkt.data.data.win << s_win_scale
    option_list = [tcp_option_window_scale_payload(s_win_scale),
                   tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    if not s_start_seq < 0:
        s_syn_ack_pkt.data.data.seq = s_start_seq
    s_syn_ack_pkt = craft_tcp_packet_with_options(s_syn_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_syn_ack_pkt, 1, 2, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)

    # c_ack_pkt = copy.deepcopy(t_c_first_ack_pkt)
    c_ack_pkt = duplicate_tcp_pkt(c_syn_pkt, s_syn_ack_pkt.data.data.ack,
                                  inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1))
    # c_ack_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    options_list = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 3, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1))
    assert actual_server_rwnd == tcpsession.get_server_scaled_window_size()
    assert actual_client_rwnd == tcpsession.get_client_scaled_window_size()
    return tcpsession, 0, actual_client_rwnd, actual_server_rwnd


def test_tcp_slide_win_with_scale_options(debug=False):

    """
        1) sliding window cases
        2) data more than window sizes
    """
    tcpsession, tick, actual_client_rwnd, actual_server_rwnd = test_tcp_with_options_handshake(debug)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_win_left_edge = last_c_pkt.data.data.ack
    s_win_left_edge = last_s_pkt.data.data.ack
    c_payload = b"A" * actual_server_rwnd
    c_payload_len = actual_server_rwnd
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, last_c_pkt.data.data.seq, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.flags, c_payload)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 4, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, c_ack_pkt.data.data.seq + c_payload_len, c_win_left_edge,
                       s_win_left_edge)
    c_win_left_edge = c_ack_pkt.data.data.ack
    """
        This test checks the case wehen receivers window is full, it should ignore the data sent by peer
    """
    # at this point server side rwnd is full (server haven't acknowledged anything)
    extra_payload_len = 5
    extra_payload = b"B" * extra_payload_len
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, last_c_pkt.data.data.seq + len(c_payload),
                                  last_c_pkt.data.data.ack, last_c_pkt.data.data.flags, extra_payload)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 4, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, c_ack_pkt.data.data.seq)
    c_win_left_edge = c_ack_pkt.data.data.ack

    # server acknowledges the data
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, last_c_pkt.data.data.ack, last_c_pkt.data.data.seq + c_payload_len)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, 5, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       s_ack_pkt.data.data.seq, s_ack_pkt.data.data.ack, c_win_left_edge,
                       s_ack_pkt.data.data.ack)
    s_win_left_edge = s_ack_pkt.data.data.ack

    # client re-attempts the previously ignored packet, technically we would need to update the timestamp
    # but we can assume this is all happening pretty fast and clock has not ticked yet
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 6, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, last_s_pkt.data.data.ack + extra_payload_len,
                       c_win_left_edge, s_win_left_edge)
    c_win_left_edge = c_ack_pkt.data.data.ack
    """ Test for retransmission of a packet with options, expectation is if timestamps is different, packet
        with empty packet should be stored in session. If timestamps is same, it's safe to discard the packet
        form session.
    """
    # this case is for retransmission with payload
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 6, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, last_s_pkt.data.data.ack + extra_payload_len,
                       c_win_left_edge, s_win_left_edge)
    tick = 1
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val + tick, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 7, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, last_s_pkt.data.data.ack + extra_payload_len,
                       c_win_left_edge, s_win_left_edge)
    c_win_left_edge = c_ack_pkt.data.data.ack

    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(s_ack_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + extra_payload_len)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val + tick, c_start_timestamp_val + tick)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, 8, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, s_ack_pkt.data.data.ack, c_ack_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    # this case is of retransmission without payload
    verify_tcp_session(tcpsession, s_ack_pkt, 1, 8, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, s_ack_pkt.data.data.ack, c_ack_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    # this case is retransmission without payload with different timestamp, technically not a retransmission
    # because it has new timestamp but since it doesn't carry any new payload or acknowledgement it's
    # retransmission. Due to new timestamp empty packet will be store in the session
    tick += 1
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val + tick, c_start_timestamp_val + tick)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, 9, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, s_ack_pkt.data.data.ack, c_ack_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    assert tcpsession.get_server_scaled_window_size() == actual_server_rwnd
    s_win_left_edge = s_ack_pkt.data.data.ack
    # packet with payload which overlaps with left side of rwnd window
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    retran_len = 3
    c_payload_len = 5
    c_payload = b'B' * retran_len + b'C' * c_payload_len
    c_ack_pkt = duplicate_tcp_pkt(c_ack_pkt, last_s_pkt.data.data.ack - retran_len, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.flags, c_payload)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val + tick, s_start_timestamp_val + tick)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 10, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, c_ack_pkt.data.data.seq + retran_len + c_payload_len,
                       c_win_left_edge, s_win_left_edge)
    assert tcpsession.get_server_next_rcv() - tcpsession.get_server_win_left_edge() == c_payload_len

    # packet with payload which overlaps with the right side of rwnd window
    # same options list is used as previous one
    extra_payload_len = 5
    c_payload_len = actual_server_rwnd - c_payload_len + extra_payload_len
    c_payload = b'D' * (c_payload_len - extra_payload_len) + b'E' * extra_payload_len
    c_ack_pkt = duplicate_tcp_pkt(c_ack_pkt, tcpsession.get_server_next_rcv(), c_ack_pkt.data.data.ack,
                                  c_ack_pkt.data.data.flags, c_payload)
    # c_ack_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 11, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack, c_ack_pkt.data.data.seq + c_payload_len - extra_payload_len,
                       c_ack_pkt.data.data.ack, s_win_left_edge)
    # server acks the client payload
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_payload_len = 64
    s_payload = b"z" * s_payload_len
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, last_c_pkt.data.data.ack,
                                  last_c_pkt.data.data.seq + c_payload_len - extra_payload_len, payload=s_payload)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val + tick, c_start_timestamp_val + tick)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, 12, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       c_ack_pkt.data.data.ack + s_payload_len, s_ack_pkt.data.data.ack, c_ack_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    s_win_left_edge = s_ack_pkt.data.data.ack
    return tcpsession, tick


def test_tcp_with_options_piggybacked_conn_termination(debug=False):
    tcpsession, tick = test_tcp_slide_win_with_scale_options(debug)
    pkt_count = len(tcpsession.get_sessions()[tcpsession.get_session_count()])
    actual_client_rwnd = tcpsession.get_client_scaled_window_size()
    actual_server_rwnd = tcpsession.get_server_scaled_window_size()
    # send a packet ahead of rcv_next to client, with same option list
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_payload_len = 64
    s_payload = b'x' * s_payload_len
    ahead_offset = 10
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt,
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq,
                                                     len(last_s_pkt.data.data.data) + ahead_offset),
                                  last_s_pkt.data.data.ack, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN,
                                  payload=s_payload)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val + tick, c_start_timestamp_val + tick)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       last_c_pkt.data.data.ack + len(last_s_pkt.data.data.data),
                       s_ack_pkt.data.data.ack, last_c_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    # server sends the packet to fill the hole, special case here is server's ahead of seq num packet crosses the
    # clients rwnd right end, expected here is that client should ignore that extra payload
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_hole_payload = b'y' * ahead_offset
    s_hole_payload_len = ahead_offset
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(), last_s_pkt.data.data.ack,
                                  payload=s_hole_payload)
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2, TCPState.ESTABLISHED, TCPState.FIN_WAIT_1,
                       inc_tcp_seq_number(last_c_pkt.data.data.ack, actual_client_rwnd),
                       s_ack_pkt.data.data.ack, last_c_pkt.data.data.ack,
                       s_ack_pkt.data.data.ack)
    assert inc_tcp_seq_number(last_c_pkt.data.data.ack, actual_client_rwnd) == tcpsession.get_client_next_rcv()
    return tcpsession, tick


def test_tcp_with_options_termination_client(debug=False):
    tcpsession, tick = test_tcp_with_options_piggybacked_conn_termination(debug)
    pkt_count = len(tcpsession.get_sessions()[tcpsession.get_session_count()])
    actual_client_rwnd = tcpsession.get_client_scaled_window_size()
    actual_server_rwnd = tcpsession.get_server_scaled_window_size()
    # terminate the connection
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, last_s_pkt.data.data.ack, tcpsession.get_client_next_rcv(),
                                  dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val + tick, s_start_timestamp_val + tick)]
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, option_list)
    verify_tcp_session(tcpsession, c_fin_pkt, 1, pkt_count + 1, TCPState.LAST_ACK, TCPState.FIN_WAIT_2,
                       c_fin_pkt.data.data.ack, last_s_pkt.data.data.ack, c_fin_pkt.data.data.ack,
                       last_s_pkt.data.data.ack)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, last_c_pkt.data.data.ack,
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, 1))
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val + tick, c_start_timestamp_val + tick)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, 1, pkt_count + 2, TCPState.CLOSED, TCPState.CLOSED,
                       s_ack_pkt.data.data.seq, s_ack_pkt.data.data.ack, s_ack_pkt.data.data.seq,
                       s_ack_pkt.data.data.ack)
    return tcpsession


def test_tcp_with_options_termination_client_with_stale_fin(debug=False):
    tcpsession, tick = test_tcp_with_options_piggybacked_conn_termination(debug)
    pkt_count = len(tcpsession.get_sessions()[tcpsession.get_session_count()])
    actual_client_rwnd = tcpsession.get_client_scaled_window_size()
    actual_server_rwnd = tcpsession.get_server_scaled_window_size()
    # terminate the connection
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, last_s_pkt.data.data.ack - 1, tcpsession.get_client_next_rcv(),
                                  dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val + tick, s_start_timestamp_val + tick)]
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, option_list)
    verify_tcp_session(tcpsession, c_fin_pkt, 1, pkt_count, TCPState.ESTABLISHED, TCPState.FIN_WAIT_1,
                       tcpsession.get_client_next_rcv(), last_s_pkt.data.data.ack,
                       tcpsession.get_client_win_left_edge(),
                       last_s_pkt.data.data.ack)

    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, last_s_pkt.data.data.ack, tcpsession.get_client_next_rcv(),
                                  dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
    option_list = [tcp_option_time_stamp_payload(c_start_timestamp_val + tick, s_start_timestamp_val + tick)]
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, option_list)
    verify_tcp_session(tcpsession, c_fin_pkt, 1, pkt_count + 1, TCPState.LAST_ACK, TCPState.FIN_WAIT_2,
                       c_fin_pkt.data.data.ack, last_s_pkt.data.data.ack, c_fin_pkt.data.data.ack,
                       last_s_pkt.data.data.ack)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())


""" write test case for wrapped around window
        1) tcp.seq and tcp.seq + len(tcp.payload) wraps around, and rcv_next overlaps with this window
            *) there will be a case when rcv_next = tcp.seq and one will be where it not
        2) rcv_next and window_right_end wraps around, and tcp.seq + len(tcp.payload) overlaps with the window
            *) there will be 3 edge case, payload before, at the end and after the end of window
        Above two tests are tested in: test_tcp_with_options_wrap_around_cases()
        3) when tcp.seq in rwnd, and it fills a hole in the window -- basically tests the 1st case but from waiting
            queue
        above test is tested in test_tcp_with_options_wraparound_handshake()
"""
""" Test case for when FIN PKT/ACK is delivered early,
        *) When both the peers are in ESTABLISHED state - 2 cases
        *) When one is in FIN_WAIT_1 - 2 cases for both sides
            *) Transition to FIN_WAIT_2
            *) Transition to CLOSING state
        *) When one is in FIN_WAIT_2 - 2 cases for both sides
        These cases are covered in early connection termination cases
"""
""" Test cases that needs to be tested, from each side of peer, can be combined with wrap around window case
    *) FIN with stale seq number
        *) Standalone FIN (covered in test_tcp_with_options_wraparound_4_way_termination(),
                            and test_tcp_with_options_wraparound_4_way_s_termination())
        *) Piggy-backed FIN
    *) FIN ACK with stale seq number
    *) FIN - FIN for the case of CLOSING state with stale seq number
    *) LAST_ACK state ACK with  stale (covered in test_tcp_with_options_wraparound_handshake())
    Thsese cases are covered below in wrap around cases
"""


def test_tcp_with_options_wraparound_handshake(debug=False, c_start_seq=MAX_SEQ_NUM, s_start_seq=MAX_SEQ_NUM):
    tcpsession, tick, c_rwnd, s_rwnd = test_tcp_with_options_handshake(debug, c_start_seq, s_start_seq)
    assert tcpsession.get_server_win_left_edge() == inc_tcp_seq_number(c_start_seq, 1)
    assert tcpsession.get_server_next_rcv() == inc_tcp_seq_number(c_start_seq, 1)
    assert tcpsession.get_client_win_left_edge() == inc_tcp_seq_number(s_start_seq, 1)
    assert tcpsession.get_client_next_rcv() == inc_tcp_seq_number(s_start_seq, 1)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    pkt_count = len(tcpsession.get_sessions()[tcpsession.get_session_count()])
    c_win_left_edge = tcpsession.get_client_win_left_edge()
    s_win_left_edge = tcpsession.get_server_win_left_edge()
    payload_len = 10
    payload = b'A' * payload_len
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(), last_c_pkt.data.data.ack,
                                  payload=payload)
    c_options = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, c_options)
    verify_tcp_session(tcpsession, c_ack_pkt, tcpsession.get_session_count(), pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED,
                       exp_s_rcv_next=inc_tcp_seq_number(c_ack_pkt.data.data.seq, payload_len),
                       exp_s_win_left_edge=s_win_left_edge)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    stale_payload_len = 5
    stale_payload = b's' * stale_payload_len
    payload = b'B' * payload_len
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, inc_tcp_seq_number(tcpsession.get_client_next_rcv(),
                                                                 0 - stale_payload_len - 1),
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, payload_len),
                                  payload=stale_payload + payload)
    s_options = [tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 2, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED,
                       exp_c_rcv_next=inc_tcp_seq_number(s_ack_pkt.data.data.seq, stale_payload_len + payload_len),
                       exp_s_rcv_next=inc_tcp_seq_number(last_c_pkt.data.data.seq, payload_len),
                       exp_c_win_left_edge=c_win_left_edge,
                       exp_s_win_left_edge=s_ack_pkt.data.data.ack)
    # send an early packet
    hole_payload_len = 60
    hole_payload = b"C" * hole_payload_len
    early_payload_len = 10
    early_payload = b"D" * early_payload_len
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    early_c_ack_pkt = duplicate_tcp_pkt(last_c_pkt,
                                        inc_tcp_seq_number(tcpsession.get_server_next_rcv(), hole_payload_len),
                                        last_c_pkt.data.data.ack,
                                        payload=early_payload)
    early_c_ack_pkt = craft_tcp_packet_with_options(early_c_ack_pkt, c_options)
    verify_tcp_session(tcpsession, early_c_ack_pkt, tcpsession.get_session_count(), pkt_count + 2,
                       TCPState.ESTABLISHED, TCPState.ESTABLISHED, tcpsession.get_client_next_rcv(),
                       tcpsession.get_server_next_rcv(), tcpsession.get_client_win_left_edge(),
                       tcpsession.get_server_win_left_edge())
    # send packet that fills the hole
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    hole_c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(), last_c_pkt.data.data.ack,
                                       payload=hole_payload)
    hole_c_ack_pkt = craft_tcp_packet_with_options(hole_c_ack_pkt, c_options)
    server_next_rcv = inc_tcp_seq_number(tcpsession.get_server_next_rcv(),
                                         min(hole_payload_len + early_payload_len,
                                             tcpsession.get_server_scaled_window_size()))
    verify_tcp_session(tcpsession, hole_c_ack_pkt, tcpsession.get_session_count(), pkt_count + 4,
                       TCPState.ESTABLISHED, TCPState.ESTABLISHED, tcpsession.get_client_next_rcv(),
                       server_next_rcv, tcpsession.get_client_win_left_edge(),
                       tcpsession.get_server_win_left_edge())
    # Server acknowledges the data
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(), server_next_rcv)
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 5, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), s_ack_pkt.data.data.ack)
    return tcpsession, pkt_count + 5, c_options, s_options, payload_len


def test_tcp_with_options_wraparound_4_way_termination(debug=False, c_start_seq=MAX_SEQ_NUM,
                                                       s_start_seq=MAX_SEQ_NUM):
    tcpsession, pkt_count, c_options, \
    s_options, payload_len = test_tcp_with_options_wraparound_handshake(debug, c_start_seq, s_start_seq)
    # test for FIN with stale seq number
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(),
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq,
                                                     get_tcp_packet_payload_len(last_s_pkt)),
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN, payload=b"")
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, c_options)
    c_fin_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, c_fin_pkt, tcpsession.get_session_count(), pkt_count, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    """
    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(),
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq,
                                                     get_tcp_packet_payload_len(last_s_pkt)),
                                  dpkt.tcp.TH_ACK|dpkt.tcp.TH_FIN, payload=b"")
    """
    c_fin_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, 1)
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, c_options)
    verify_tcp_session(tcpsession, c_fin_pkt, tcpsession.get_session_count(), pkt_count + 1, TCPState.FIN_WAIT_1,
                       TCPState.ESTABLISHED, inc_tcp_seq_number(last_s_pkt.data.data.seq,
                                                                get_tcp_packet_payload_len(last_s_pkt)),
                       tcpsession.get_server_next_rcv(),
                       inc_tcp_seq_number(last_s_pkt.data.data.seq, get_tcp_packet_payload_len(last_s_pkt)),
                       tcpsession.get_server_win_left_edge())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(),
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, 1), dpkt.tcp.TH_ACK, b"")
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 2, TCPState.FIN_WAIT_2,
                       TCPState.CLOSE_WAIT, tcpsession.get_client_next_rcv(), s_ack_pkt.data.data.ack,
                       tcpsession.get_client_win_left_edge(), s_ack_pkt.data.data.ack)
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(),
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, 1),
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN, b"")
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 2, TCPState.FIN_WAIT_2,
                       TCPState.CLOSE_WAIT, tcpsession.get_client_next_rcv(), s_ack_pkt.data.data.ack,
                       tcpsession.get_client_win_left_edge(), s_ack_pkt.data.data.ack)
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(),
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, 1),
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN, b"")
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 3, TCPState.FIN_WAIT_2,
                       TCPState.LAST_ACK, tcpsession.get_client_next_rcv(), s_ack_pkt.data.data.ack,
                       tcpsession.get_client_win_left_edge(), s_ack_pkt.data.data.ack)
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(),
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq, 1), payload=b"")
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, c_options)
    c_ack_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, c_ack_pkt, tcpsession.get_session_count(), pkt_count + 3, TCPState.FIN_WAIT_2,
                       TCPState.LAST_ACK, tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(),
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq, 1), payload=b"")
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, c_options)
    verify_tcp_session(tcpsession, c_ack_pkt, tcpsession.get_session_count(), pkt_count + 4, TCPState.CLOSED,
                       TCPState.CLOSED, c_ack_pkt.data.data.ack, tcpsession.get_server_next_rcv(),
                       c_ack_pkt.data.data.ack, tcpsession.get_server_win_left_edge())


def test_tcp_with_options_wraparound_4_way_s_termination(debug=False, c_start_seq=MAX_SEQ_NUM,
                                                         s_start_seq=MAX_SEQ_NUM):
    tcpsession, pkt_count, c_options, \
    s_options, payload_len = test_tcp_with_options_wraparound_handshake(debug, c_start_seq, s_start_seq)
    # test for FIN with stale seq number, from server side
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_fin_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(),
                                  last_s_pkt.data.data.ack,
                                  dpkt.tcp.TH_ACK | dpkt.tcp.TH_FIN, payload=b"")
    s_fin_pkt = craft_tcp_packet_with_options(s_fin_pkt, s_options)
    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_fin_pkt, tcpsession.get_session_count(), pkt_count, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    s_fin_pkt.data.data.seq = inc_tcp_seq_number(s_fin_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, s_fin_pkt, tcpsession.get_session_count(), pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.FIN_WAIT_1, s_fin_pkt.data.data.seq,
                       tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    # client sends stale FIN and ACK to servers FIN
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    c_fin_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(),
                                  inc_tcp_seq_number(last_s_pkt.data.data.seq, 1),
                                  dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
    c_fin_pkt = craft_tcp_packet_with_options(c_fin_pkt, c_options)
    c_fin_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, c_fin_pkt, tcpsession.get_session_count(), pkt_count + 1, TCPState.ESTABLISHED,
                       TCPState.FIN_WAIT_1, tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    c_fin_pkt.data.data.seq = inc_tcp_seq_number(c_fin_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, c_fin_pkt, tcpsession.get_session_count(), pkt_count + 2, TCPState.LAST_ACK,
                       TCPState.FIN_WAIT_2, c_fin_pkt.data.data.ack, tcpsession.get_server_next_rcv(),
                       c_fin_pkt.data.data.ack, tcpsession.get_server_win_left_edge())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(),
                                  inc_tcp_seq_number(last_c_pkt.data.data.seq, 1), payload=b"")
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, s_options)
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, -1)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 2,
                       TCPState.LAST_ACK, TCPState.FIN_WAIT_2,
                       tcpsession.get_client_next_rcv(), tcpsession.get_server_next_rcv(),
                       tcpsession.get_client_win_left_edge(), tcpsession.get_server_win_left_edge())
    s_ack_pkt.data.data.seq = inc_tcp_seq_number(s_ack_pkt.data.data.seq, 1)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), pkt_count + 3,
                       TCPState.CLOSED, TCPState.CLOSED, tcpsession.get_client_next_rcv(),
                       s_ack_pkt.data.data.ack, tcpsession.get_client_win_left_edge(),
                       s_ack_pkt.data.data.ack)


def test_tcp_with_options_wrap_around_cases(debug=False):
    test_tcp_with_options_wraparound_handshake(debug)
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 1, MAX_SEQ_NUM - 1)
    # this is the wrap around case for FIN flag, extra 10 is used because payload size used in underlying function
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 11, MAX_SEQ_NUM - 11)
    # this the case when seq + payload wraps around
    test_tcp_with_options_wraparound_handshake(debug, c_start_seq=MAX_SEQ_NUM - 5, s_start_seq=MAX_SEQ_NUM - 5)
    test_tcp_with_options_wraparound_4_way_s_termination(debug, MAX_SEQ_NUM - 1, MAX_SEQ_NUM - 1)
    test_tcp_with_options_wraparound_4_way_s_termination(debug, MAX_SEQ_NUM - 11, MAX_SEQ_NUM - 11)
    # this is the case where hole needs to wrap around
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 20, MAX_SEQ_NUM - 11)
    # this is the case where early packet needs to be wrapped around
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 30, MAX_SEQ_NUM - 11)
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 74, MAX_SEQ_NUM - 11)
    test_tcp_with_options_wraparound_4_way_termination(debug, MAX_SEQ_NUM - 73, MAX_SEQ_NUM - 11)


def test_tcp_mss_with_options(debug=False):
    tcpsession = TCPSession("", sip, dip, sport, dport)
    if debug:
        tcpsession.set_print_debug_info()
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    c_syn_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    c_win_scale = 7
    # actual client rwnd is of 128 bytes
    actual_client_rwnd = c_syn_pkt.data.data.win << c_win_scale
    c_mss = 30
    option_list = [tcp_option_mss_paylod(c_mss),
                   tcp_option_window_scale_payload(c_win_scale),
                   tcp_option_time_stamp_payload(c_start_timestamp_val, 0),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    c_syn_pkt = craft_tcp_packet_with_options(c_syn_pkt, option_list)
    verify_tcp_session(tcpsession, c_syn_pkt, 1, 1, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)
    assert tcpsession.get_client_scaled_window_size() == actual_client_rwnd
    assert tcpsession.get_client_mss() == c_mss
    s_syn_ack_pkt = duplicate_tcp_pkt(t_syn_ack_pkt, t_syn_ack_pkt.data.data.seq,
                                      inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1),
                                      dpkt.tcp.TH_ACK | dpkt.tcp.TH_SYN)
    s_syn_ack_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    s_win_scale = 6
    # actual server rwnd is of 64 bytes
    actual_server_rwnd = s_syn_ack_pkt.data.data.win << s_win_scale
    option_list = [tcp_option_mss_paylod(TCP_MSS_DEFAULT),
                    tcp_option_window_scale_payload(s_win_scale),
                   tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    s_syn_ack_pkt = craft_tcp_packet_with_options(s_syn_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_syn_ack_pkt, 1, 2, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)
    assert tcpsession.get_server_mss() == TCP_MSS_DEFAULT

    c_ack_pkt = duplicate_tcp_pkt(c_syn_pkt, s_syn_ack_pkt.data.data.ack,
                                  inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1))
    options_list = [tcp_option_time_stamp_payload(c_start_timestamp_val, s_start_timestamp_val)]
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, 1, 3, TCPState.ESTABLISHED, TCPState.ESTABLISHED,
                       inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(s_syn_ack_pkt.data.data.seq, 1),
                       inc_tcp_seq_number(c_syn_pkt.data.data.seq, 1))
    last_s_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_s_pkt())
    last_c_pkt = dpkt.ethernet.Ethernet(tcpsession.get_last_c_pkt())
    payload_len = 30
    payload = b"A" * payload_len
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(), last_s_pkt.data.data.ack,
                                  payload=payload)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), 3, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, 0, 0)
    payload_len = 19
    payload = b"A" * payload_len
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(), last_s_pkt.data.data.ack,
                                  payload=payload)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), 3, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, 0, 0)
    payload_len = 18
    payload = b"A" * payload_len
    s_ack_pkt = duplicate_tcp_pkt(last_s_pkt, tcpsession.get_client_next_rcv(), last_s_pkt.data.data.ack,
                                  payload=payload)
    option_list = [tcp_option_time_stamp_payload(s_start_timestamp_val, c_start_timestamp_val)]
    s_ack_pkt = craft_tcp_packet_with_options(s_ack_pkt, option_list)
    verify_tcp_session(tcpsession, s_ack_pkt, tcpsession.get_session_count(), 4, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, total_c_data_len=0, total_s_data_len=18)
    payload_len = tcpsession.get_server_mss() - len(tcp_option_payload_creation(option_list)) + 1
    payload = b"B" * payload_len
    c_ack_pkt = duplicate_tcp_pkt(last_c_pkt, tcpsession.get_server_next_rcv(), last_c_pkt.data.data.ack,
                                  payload=payload)
    c_ack_pkt = craft_tcp_packet_with_options(c_ack_pkt, option_list)
    verify_tcp_session(tcpsession, c_ack_pkt, tcpsession.get_session_count(), 4, TCPState.ESTABLISHED,
                       TCPState.ESTABLISHED, total_c_data_len=0, total_s_data_len=18)


def test_seq_number_off_by_window():
    # Cases when window doesn't wraps around
    win_start_seq = 0xFFFFFFF0
    window_size = 8
    assert seq_number_off_by_window(0xFFFFFFF0, win_start_seq, window_size) == 0
    assert seq_number_off_by_window(0xFFFFFFF7, win_start_seq, window_size) == -7
    assert seq_number_off_by_window(0xFFFFFFF6, win_start_seq, window_size) == -6
    # ahead of window cases
    assert seq_number_off_by_window(0xFFFFFFF8, win_start_seq, window_size) == 1
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == 8
    assert seq_number_off_by_window(0, win_start_seq, window_size) == 1
    assert seq_number_off_by_window(0x07, win_start_seq, window_size) == 8
    # 1 window behind cases
    assert seq_number_off_by_window(0xFFFFFFEF, win_start_seq, window_size) == 1
    assert seq_number_off_by_window(0xFFFFFFE8, win_start_seq, window_size) == 8
    # 2 window behind cases, now it's consdiered ahead of the current window
    assert seq_number_off_by_window(0xFFFFFFE7, win_start_seq, window_size) == 8
    assert seq_number_off_by_window(0xFFFFFFE0, win_start_seq, window_size) == 1

    # cases when window wraps around
    window_size = 16
    win_start_seq = 0xFFFFFFF8  # ends at 0x07 inclusive, next start position would be 0x08
    assert seq_number_off_by_window(0xFFFFFFF8, win_start_seq, window_size) == 0
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == -7
    assert seq_number_off_by_window(0, win_start_seq, window_size) == -8
    assert seq_number_off_by_window(7, win_start_seq, window_size) == -15
    # ahead of window cases
    assert seq_number_off_by_window(8, win_start_seq, window_size) == 1
    assert seq_number_off_by_window(0x0F, win_start_seq, window_size) == 8
    assert seq_number_off_by_window(0x17, win_start_seq, window_size) == 0x10
    assert seq_number_off_by_window(0x18, win_start_seq, window_size) == 0x1
    # cases when next window wraps around, but doesn't wrap around exactly 0xFFFFFFFF
    win_start_seq = 0xFFFFFFF0
    window_size = 10
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == 6
    assert seq_number_off_by_window(0x00, win_start_seq, window_size) == 7
    assert seq_number_off_by_window(0x02, win_start_seq, window_size) == 9
    assert seq_number_off_by_window(0x03, win_start_seq, window_size) == 10
    win_start_seq = 10
    window_size = 16
    assert seq_number_off_by_window(0x09, win_start_seq, window_size) == 1
    assert seq_number_off_by_window(0x00, win_start_seq, window_size) == 10
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == 11
    assert seq_number_off_by_window(0xFFFFFFFA, win_start_seq, window_size) == 16
    assert seq_number_off_by_window(0xFFFFFFF9, win_start_seq, window_size) == 16
    assert seq_number_off_by_window(0xFFFFFFEA, win_start_seq, window_size) == 1

    # window doesn't wrap around exactly at 0xFFFFFFFF
    win_start_seq = 10
    window_size = 10
    assert seq_number_off_by_window(0x00, win_start_seq, window_size) == 10
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == 6
    win_start_seq = 8
    window_size = 10
    # previous window cases
    assert seq_number_off_by_window(0x00, win_start_seq, window_size) == 8
    assert seq_number_off_by_window(0xFFFFFFFF, win_start_seq, window_size) == 9
    assert seq_number_off_by_window(0xFFFFFFFE, win_start_seq, window_size) == 10
    # ahead of window case
    assert seq_number_off_by_window(0xFFFFFFFD, win_start_seq, window_size) == 6
    assert seq_number_off_by_window(0xFFFFFFF8, win_start_seq, window_size) == 1


def test_tcp_retransmission_from_pcap():
    in_pcap_file = "data/100.1.21.181-7201-200.1.9.163-80-session.pcap"
    data_file = "data/100.1.21.181-7201-200.1.9.163-80-session.data"
    sip = b'\x64\x01\x15\xb5'
    dip = b'\xc8\x01\x09\xa3'
    sport = 7201
    dport = 80
    out_pcap_file = "data/test_output.pcap"
    tcpsession = TCPSession(in_pcap_file, sip, dip, sport, dport)
    tcpsession.process()
    session = tcpsession.get_session(0)
    tcpsession.write_sessions("data/temp_test.pcap")
    assert len(tcpsession.get_sessions().keys()) == 1
    session_data = []
    with open(data_file) as data_fp:
        while True:
            line = data_fp.readline()
            if not line:
                break
            line = line.strip('\n')
            session_data.append(binascii.unhexlify(line))
    assert len(session) == len(session_data)
    total_data_from_client_and_server = 0
    for i in range(len(session_data)):
        assert get_tcp_packet_payload(session[i][1]) == session_data[i]
        total_data_from_client_and_server += len(session_data[i])
    session_meta_data = tcpsession.get_sessions_metadata()
    assert total_data_from_client_and_server == session_meta_data[1][0] + session_meta_data[1][1]
    assert total_data_from_client_and_server == (tcpsession.get_session_metadata(0)[0] +
                                                 tcpsession.get_session_metadata(0)[1])
    tcpsession.write_session(0, out_pcap_file)


def test_tcp_retransmission_from_pcap_1():
    in_pcap_file = "data/100.1.21.181-7201-200.1.9.163-80-session-crafted.pcap"
    data_file_1 = "data/100.1.21.181-7201-200.1.9.163-80-session.data"
    data_file_2 = "data/100.1.21.181-7201-200.1.9.163-80-session-crafted.data"
    sip = b'\x64\x01\x15\xb5'
    dip = b'\xc8\x01\x09\xa3'
    sport = 7201
    dport = 80
    tcpsession = TCPSession(in_pcap_file, sip, dip, sport, dport)
    out_pcap_file = "data/test_output-1.pcap"
    tcpsession.process()
    sessions = tcpsession.get_sessions()
    assert len(sessions) == 1
    sessions_data = dict()
    data_files = [data_file_1, data_file_2]
    for data_file in data_files:
        sessions_data[data_file] = []
        with open(data_file) as data_fp:
            while True:
                line = data_fp.readline()
                if not line:
                    break
                line = line.strip('\n')
                sessions_data[data_file].append(binascii.unhexlify(line))
    assert len(sessions[1]) == len(sessions_data[data_files[1]])
    for i in range(len(sessions_data[data_files[1]])):
        assert get_tcp_packet_payload(sessions[1][i][1]) == sessions_data[data_files[1]][i]
    tcpsession.write_session(0, out_pcap_file)

    in_pcap_file = "data/100.1.21.181-7201-200.1.9.163-80-two-sessions-merged.pcap"
    #tcpsession = TCPSession(sip, dip, sport, dport, in_pcap_file)
    tcpsession.clear()
    tcpsession.pcap = in_pcap_file
    tcpsession.process()
    sessions = tcpsession.get_sessions()
    assert len(sessions) == 2
    for s_id in sessions.keys():
        session_data = sessions_data[data_files[s_id - 1]]
        for i in range(len(session_data)):
            sessions[s_id][i][1] == session_data[i]
    out_pcap_file = "data/test_output_merged_combined_sessions.pcap"
    tcpsession.write_sessions(out_pcap_file)
    output_prefix = "data/test_output_merged_combined"
    tcpsession.write_individual_sessions(output_prefix)


def test_ip_address_conversions():
    assert str_to_inet("123.45.67.89") == b'{-CY'
    assert inet_to_str(str_to_inet("123.45.67.89")) == "123.45.67.89"
    assert str_to_inet("102::102:0:102:0:102:0") == b'\x01\x02\x00\x00' * 4
    assert inet_to_str(str_to_inet("102::102:0:102:0:102:0")) == "102::102:0:102:0:102:0"


def test_tcp_pkt_debug_info():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    c_syn_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    c_win_scale = 7
    # actual client rwnd is of 128 bytes
    actual_client_rwnd = c_syn_pkt.data.data.win << c_win_scale
    c_mss = 30
    option_list = [tcp_option_mss_paylod(c_mss),
                   tcp_option_window_scale_payload(c_win_scale),
                   tcp_option_time_stamp_payload(c_start_timestamp_val, 0),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION]
    c_syn_pkt = craft_tcp_packet_with_options(c_syn_pkt, option_list)
    payload = b"payload"
    c_syn_pkt = duplicate_tcp_pkt(c_syn_pkt, c_syn_pkt.data.data.seq, c_syn_pkt.data.data.ack, payload=payload)
    ip = t_first_syn_pkt.data
    debug_info = tcp_pkt_debug_info(c_syn_pkt.data)
    expected_info = "seq: {}, ack:{}, flag:{}, payload len: {}, payload: {}, sum: {}".format(hex(ip.data.seq),
                        hex(ip.data.ack), hex(ip.data.flags), hex(len(payload)), payload, hex(ip.data.sum))


def test_tcp_pkt_option_debug_info():
    c_syn_pkt = copy.deepcopy(t_first_syn_pkt)
    c_syn_pkt.data.data.win = dpkt.tcp.TCP_WIN_MAX >> 15
    c_win_scale = 7
    # actual client rwnd is of 128 bytes
    actual_client_rwnd = c_syn_pkt.data.data.win << c_win_scale
    c_mss = 30
    s_ack = struct.pack(">BBIIII", 5, 18, 1, 10, 20, 30)
    option_list = [tcp_option_mss_paylod(c_mss),
                   tcp_option_window_scale_payload(c_win_scale),
                   tcp_option_time_stamp_payload(c_start_timestamp_val, 0),
                   TCP_SELECTIVE_ACK_PERMITTED_OPTION,
                   s_ack, b'\x65\x02']
    c_syn_pkt = craft_tcp_packet_with_options(c_syn_pkt, option_list)
    str_repr_options = ['Kind: 0x2, name: TCP_OPT_MSS length: 4, data: 001e',
                        'Kind: 0x3, name: TCP_OPT_WSCALE length: 3, data: 07',
                        'Kind: 0x8, name: TCP_OPT_TIMESTAMP length: 10, '
                        'timestamp value: 0b6fde6a, timestamp echo reply: 00000000',
                        'Kind: 0x4, name: TCP_OPT_SACKOK length: 2, data: ',
                        'Kind: 0x5, name: TCP_OPT_SACK length: 18 left edge of block: 00000001, '
                        'right edge of block: 0000000a, left edge of block: 00000014, right edge of block: 0000001e, ',
                        'Kind: 0x65, name: UKNOWN_OPTION_101, len: 2, data: ',
                        'Kind: 0x1, name: TCP_OPT_NOP ']
    assert tcp_pkt_options_debug_info(c_syn_pkt.data.data) == "Options: " + str(str_repr_options)


def test_network_tuple_hash():
    src_ip = "192.168.200.100"
    dst_ip = "194.168.200.100"
    sport = "5000"
    dport = "5000"
    proto = dpkt.ip.IP_PROTO_TCP
    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(dst_ip), sport, dport, proto)
    test_dict = dict()
    test_dict[net_tuple] = ""
    reverse_net_tuple = NetworkTuple(str_to_inet(dst_ip), str_to_inet(src_ip), dport, sport, proto)
    assert reverse_net_tuple == net_tuple
    assert reverse_net_tuple in test_dict.keys()
    assert test_dict[reverse_net_tuple] == ""
    test_dict[reverse_net_tuple] = 1
    assert test_dict[net_tuple] == 1
    assert repr(net_tuple) != repr(reverse_net_tuple)

    # test for same src and only port is different
    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(src_ip), 4000, 3000, proto)
    reverse_net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(src_ip), 3000, 4000, proto)
    test_dict = dict()
    test_dict[net_tuple] = ""
    assert net_tuple == reverse_net_tuple
    assert repr(net_tuple) != repr(reverse_net_tuple)
    assert reverse_net_tuple in test_dict.keys()
    assert test_dict[reverse_net_tuple] == ""
    test_dict[reverse_net_tuple] = 1
    assert test_dict[net_tuple] == 1

    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(src_ip), 3000, 3000, proto)
    reverse_net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(src_ip), 3000, 3000, proto)
    test_dict = dict()
    test_dict[net_tuple] = ""
    assert net_tuple == reverse_net_tuple
    assert repr(net_tuple) == repr(reverse_net_tuple)

    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(dst_ip), 4000, 3000, proto)
    net_tuple_1 = NetworkTuple(str_to_inet(src_ip), str_to_inet(src_ip), 4000, 3000, proto)
    test_dict = dict()
    test_dict[net_tuple] = ""
    assert net_tuple != net_tuple_1
    assert net_tuple_1 not in test_dict.keys()
    test_dict[net_tuple_1] = 1
    assert test_dict[net_tuple] != test_dict[net_tuple_1]

    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(dst_ip), 4000, 3000, proto)
    net_tuple_1 = NetworkTuple(str_to_inet(src_ip), str_to_inet(dst_ip), 3000, 4000, proto)
    assert net_tuple != net_tuple_1

    net_tuple = NetworkTuple(str_to_inet(src_ip), str_to_inet(dst_ip), 4000, 3000, proto)
    net_tuple_1 = NetworkTuple(str_to_inet(dst_ip), str_to_inet(src_ip), 3000, 4000, proto)
    assert net_tuple == net_tuple_1


def test_tcpsessions():
    proto = dpkt.ip.IP_PROTO_TCP
    #tcpsession, tick , actual_client_rwnd, actual_server_rwnd  = test_tcp_with_options_handshake()
    tcpsession = test_tcp_with_options_termination_client()
    input_pkts = list()
    input_pkts.extend(tcpsession.get_sessions_list()[0])
    tcpsessions = TCPSessions("")
    tcpsessions.process_pkts(input_pkts)
    input_network_tuple = NetworkTuple(str_to_inet(tcpsession.sip), str_to_inet(tcpsession.dip), tcpsession.sp,
                                       tcpsession.dp, proto)
    assert tcpsessions.get_session_count(input_network_tuple) == 1
    assert tcpsessions.get_total_session_count() == 1
    assert tcpsession.get_sessions_list()[0][5][1] == tcpsessions.get_sessions(input_network_tuple)[0][5][1]
    pre_processed_list = tcpsession.get_sessions_list()
    post_processed_list = tcpsessions.get_sessions(input_network_tuple)
    for i in range(len(post_processed_list)):
        for j in range(len(pre_processed_list[i])):
            assert pre_processed_list[i][j][1] == post_processed_list[i][j][1]
    #assert tcpsessions.get_sessions(input_network_tuple) == tcpsession.get_sessions_list()

    in_pcap_file = "data/100.1.21.181-7201-200.1.9.163-80-session.pcap"
    sip = b'\x64\x01\x15\xb5'
    dip = b'\xc8\x01\x09\xa3'
    sport = 7201
    dport = 80
    out_pcap_file = "data/test_output.pcap"
    tcpsession1 = TCPSession(in_pcap_file, sip, dip, sport, dport)
    tcpsession1.process()
    session = tcpsession1.get_session(0)
    tcpsessions.process_pkts(session)
    input_network_tuple_1 = NetworkTuple(sip, dip, sport, dport, proto)
    assert tcpsessions.get_total_session_count() == 2
    assert tcpsessions.get_session_count(input_network_tuple_1) == 1
    assert tcpsessions.get_session_count(input_network_tuple) == 1
    _sessions = tcpsessions.get_sessions(input_network_tuple_1)[0]
    for i in range(len(session)):
        _sessions[i][1] == session[i][1]
    #assert tcpsessions.get_sessions(input_network_tuple_1)[0] == session[1]
    all_sessions = tcpsessions.get_all_sessions()
    pre_processed_list = [input_pkts, session]
    for i in range(len(all_sessions)):
        for j in range(len(all_sessions[i])):
            all_sessions[i][j][1] == pre_processed_list[i][j][1]
    #assert tcpsessions.get_all_sessions() == [input_pkts, session]
    tcpsessions.process_pkts(input_pkts)
    assert tcpsessions.get_total_session_count() == 3
    assert tcpsessions.get_session_count(input_network_tuple) == 2
    test_out_dir = "data/test_output_1"
    if os.path.exists(test_out_dir):
        shutil.rmtree(test_out_dir)
    tcpsessions.dump_all_sessions(test_out_dir)
    #tcpsessions.sessions[input_network_tuple].write_sessions("data/test_output_network_tuple.pcap")


def test_tcpsessions_with_pcap():
    input_pcap = "data/100.1.1.105-and-100.1.21.181-and-100.1.29.36-sessions.pcap"
    tcpsessions = TCPSessions(input_pcap)
    tcpsessions.process_pcap()
    assert tcpsessions.get_total_session_count() == 3
    print(tcpsessions.get_unique_network_tuples())
    assert tcpsessions.get_unique_network_tuples() == ['100.1.1.105_39496-200.1.20.195_80-6',
                                                       '100.1.21.181_7201-200.1.9.163_80-6',
                                                       '100.1.29.36_12374-200.1.62.190_80-6']
    all_session_pkts = list()
    for stream_num, _tcpsession, network_tuple in tcpsessions.streams.values():
        tcpsession = TCPSession(input_pcap, network_tuple.sip, network_tuple.dip, network_tuple.sp,
                            network_tuple.dp)
        tcpsession.process()
        session_pkts = tcpsession.get_session(0)
        assert tcpsessions.get_sessions(network_tuple) == [session_pkts]
        all_session_pkts.append(session_pkts)
    assert all_session_pkts == tcpsessions.get_all_sessions()
    test_out_dir = "data/test_output"
    if os.path.exists(test_out_dir):
        shutil.rmtree(test_out_dir)
    tcpsessions.dump_all_sessions(test_out_dir)
    shutil.rmtree(test_out_dir)


def test_write_sessions():
    input_pcap = "data/100.1.21.181-7201-200.1.9.163-80-two-sessions-merged.pcap"
    tcpsessions = TCPSessions(input_pcap)
    tcpsessions.process_pcap()
    assert tcpsessions.get_total_session_count() == 2
    assert tcpsessions.get_unique_network_tuples() == ['100.1.21.181_7201-200.1.9.163_80-6']
    out_dir = "data/test_output/"
    rm_dir = False
    prefix = "test_out"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
        rm_dir = True
    else:
        shutil.rmtree(out_dir)
        os.makedirs(out_dir)
    tcpsessions.write_all_sessions(out_dir, prefix)
    for i in range(tcpsessions.get_total_session_count()):
        output_file_name = "{}_{}_{}.pcap".format(prefix, tcpsessions.get_unique_network_tuples()[0], i)
        output_file_name = os.path.join(out_dir, output_file_name)
        assert os.path.isfile(output_file_name)
        os.remove(output_file_name)
    tcpsessions.write_session(0, out_dir, prefix)
    output_file_name = os.path.join(out_dir, "{}_{}.pcap".format(prefix, tcpsessions.get_unique_network_tuples()[0]))
    assert os.path.isfile(output_file_name)
    os.remove(output_file_name)
    if rm_dir:
        shutil.rmtree(out_dir)
