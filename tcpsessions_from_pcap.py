import socket
import struct
import subprocess
import timeit
import glob
import json
import os
import argparse
import logging
import shutil
import tarfile
from tcpsession.tcpsession import TCPSessions, NetworkTuple
from datetime import datetime
from hashlib import md5, sha256
LOG_FORMAT_STRING = '%(asctime)s %(levelname)-8s %(filename)s %(lineno)d %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
EMPTY_FILE_MD5_SUM = "d41d8cd98f00b204e9800998ecf8427e"
TMP_PCAP_EXTR_DIR = "pcap_extraction"
TMP_TCPSESSION_EXTR_DIR = "tcpsession"
TMP_TCPFLOW_EXTR_DIR = "tcpflow"
TMP_JS_EXTR_DIR = "js_extraction"
TMP_WS_EXTR_DIR = "wireshark"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT_STRING, datefmt=LOG_DATEFMT,
                    filename=os.path.splitext(os.path.basename(__file__))[0] + ".log", filemode="w")
logger = logging.getLogger(__name__)


def str_to_inet(ip: str) -> bytes:
    """
    Converts a string representation of IP address to binary representation.
    :param ip: IP like - "123.45.67.89"
    :return: 32 bit representation of "123.45.67.89" like - '{-CY'
    """
    try:
        return socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        return socket.inet_pton(socket.AF_INET6, ip)


def inet_to_str(inet) -> str:
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def extract_data_with_tcpsessions(pcap, out_dir) ->TCPSessions:
    """Extracts the TCP sessions using TCPSessions class.
    :param pcap: input pcap to extract sessions from
    :param out_dir: directory where pcap of extracted session will be stored
    :return: Object of TCPSessions which could be used again for the given input pcap
    """
    start_time = datetime.now()
    tcpsessions = TCPSessions(pcap)
    tcpsessions.process_pcap()
    tcpsessions.dump_all_sessions(out_dir)
    logger.info("Total time taken to process pcap {} by TCPSessions is {}".format(pcap, datetime.now() - start_time))
    return tcpsessions


def extract_data_with_tcpflow(pcap, out_dir):
    """Extracts the TCP sessions using tcpflow command
    :param pcap: pcap to extract sessions from
    :param out_dir: output directory where all the results will be stored
    :return: None
    """
    cmd = "tcpflow -r {} -o {}".format(pcap, out_dir)
    logger.info("tcpflow command going to be used is {}".format(cmd))
    start_time = datetime.now()
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    logger.info("Total time taken to process the pcap {} by tcpflow is {}".format(pcap, datetime.now() - start_time))
    if output.returncode is not 0:
        logger.info("tcpflow command failed with return code: {}".format(output.returncode))
    return output.returncode


def inet_to_tcpflow_repr(net_tuple: NetworkTuple):
    sip_octets = net_tuple.get_str_sip().split(".")
    dip_octets = net_tuple.get_str_dip().split(".")
    return "{:0>3}.{:0>3}.{:0>3}.{:0>3}.{:0>5}-{:0>3}.{:0>3}.{:0>3}.{:0>3}.{:0>5}".format(sip_octets[0], sip_octets[1],
                                                            sip_octets[2], sip_octets[3],
                                                            net_tuple.sp, dip_octets[0], dip_octets[1], dip_octets[2],
                                                            dip_octets[3], net_tuple.dp)


def file_hash(file_path, hash_algo="sha256"):
    buf_size = 65536
    if hash_algo == "sha256":
        digester = sha256()
    else:
        digester = md5()
    with open(file_path, 'rb') as file_ref:
        while True:
            buf = file_ref.read(buf_size)
            if not buf:
                break
            digester.update(buf)
        return digester.hexdigest()


def verify_data_with_tcpflow(pcap, tcpsession_out_dir, tcpflow_out_dir):
    tcpsessions = extract_data_with_tcpsessions(pcap, tcpsession_out_dir)
    sessions = tcpsessions.sessions
    logger.info("Going to verify the results against tcpflow")
    if extract_data_with_tcpflow(pcap, tcpflow_out_dir) is not 0:
        logger.info("Couldn't verify against tcpflow because command execution failed")
        return
    diff_src_session_data_count = 0
    diff_dst_session_data_count = 0
    for net_tuple in sessions.keys():
        rev_net_tuple = NetworkTuple(net_tuple.dip, net_tuple.sip, net_tuple.dp, net_tuple.sp, net_tuple.proto)
        logger.info("reverse network tuple: {}".format(rev_net_tuple))
        for session_id in sessions[net_tuple].sessions.keys():
            _net_tuple = sessions[net_tuple].get_session_network_tuple(session_id - 1)
            tcpsession_json = os.path.join(tcpsession_out_dir,
                                       repr(_net_tuple) + '-' + str(session_id - 1) + ".json")
            logger.info("tcpsession json output file: {}".format(tcpsession_json))
            with open(tcpsession_json) as tcpsession_json_fp:
                tcpsession_json_obj = json.load(tcpsession_json_fp)
            if session_id == 1:
                tcpflow_src_file = os.path.join(tcpflow_out_dir, inet_to_tcpflow_repr(net_tuple))
                tcpflow_dst_file = os.path.join(tcpflow_out_dir, inet_to_tcpflow_repr(rev_net_tuple))
            else:
                tcpflow_src_file = os.path.join(tcpflow_out_dir, inet_to_tcpflow_repr(net_tuple) + "c" +
                                                str(session_id - 1))
                tcpflow_dst_file = os.path.join(tcpflow_out_dir, inet_to_tcpflow_repr(rev_net_tuple) + "c" +
                                            str(session_id - 1))
            logger.info("tcpflow src output file: {}".format(tcpflow_src_file))
            logger.info("tcpflow dst output file: {}".format(tcpflow_dst_file))
            if os.path.exists(tcpflow_src_file):
                src_data_md5sum = file_hash(tcpflow_src_file, "md5")
            else:
                logger.info("tcpflow file src file doesn't exist.")
                src_data_md5sum = EMPTY_FILE_MD5_SUM
            if src_data_md5sum == tcpsession_json_obj["combined_src_payload_md5sum"]:
                logger.info("SRC md5sum for {} is same for tcpsession and tcpflow".format(
                    str(net_tuple) + '-' + str(session_id - 1)))
            else:
                stream_id = tcpsessions.network_tuple_stream_id[net_tuple][session_id - 1]
                logger.info("In the pcap {} SRC md5sum for {} is different for tcpsession and tcpflow for stream"
                            " id: {}".format(pcap, str(net_tuple) + '-' + str(session_id - 1), stream_id - 1))
                logger.info("tcpsession src md5: {},"
                            " tcpflow src md5: {}".format(tcpsession_json_obj["combined_src_payload_md5sum"],
                                                          src_data_md5sum))
                diff_src_session_data_count += 1
            if os.path.exists(tcpflow_dst_file):
                dst_data_md5sum = file_hash(tcpflow_dst_file, "md5")
            else:
                logger.info("tcpflow file dst file doesn't exist.")
                dst_data_md5sum = EMPTY_FILE_MD5_SUM
            if dst_data_md5sum == tcpsession_json_obj["combined_dst_payload_md5sum"]:
                logger.info("DST md5sum for {} is same for tcpsession and tcpflow".format(
                    str(net_tuple) + '-' + str(session_id - 1)))
            else:
                stream_id = tcpsessions.network_tuple_stream_id[net_tuple][session_id - 1]
                logger.info("In the pcap {} DST md5sum for {} is different for tcpsession and tcpflow for stream id:"
                            " {}".format(pcap, str(net_tuple) + '-' + str(session_id - 1), stream_id - 1))
                logger.info("tcpsession dst md5: {},"
                            " tcpflow dst md5: {}".format(tcpsession_json_obj["combined_dst_payload_md5sum"],
                                                          dst_data_md5sum))
                diff_dst_session_data_count += 1
    logger.info("Number of sessions whose src/dst data was different from TCP flow"
                " is src count: {}, dst count: {}".format(diff_src_session_data_count, diff_dst_session_data_count))


def run_command(cmd: str):
    """Executes a command passed along with its argument
    :param cmd: command to run
    :return: return the 0 on success else the error code; same as subprocess.run() return code.
    """
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    if output.returncode is not 0:
        logger.info("command failed with return code {}".format(output.returncode))
    return output.returncode


def create_tar(_input: str, output_tar_name: str):
    """Creates gunzipped tar of given input.
    :param _input: input file or directory
    :param output_tar_name: name of output tar
    :return: None
    """
    if os.path.isdir(_input):
        file_list = os.listdir(_input)
    elif os.path.isfile(_input):
        file_list = [_input]
    with tarfile.open(output_tar_name, "w:gz") as tar_fp:
        for _file in file_list:
            tar_fp.add(_file)


def verify_data_with_wireshark(pcap, output_dir, performance_mode=False):
    """Verifies the correctness of sessions extracted from a pcap with the TCPSessions class against the Wireshark.
        Beware, takes long time to execute because it spawns one process for each stream.
    :param pcap: pcap to extract sessions from
    :param output_dir: directory to store pcaps of the sessions extracted with TCPSessions class
    :return:
    """
    tcpsession_out_dir = os.path.join(output_dir, TMP_TCPSESSION_EXTR_DIR)
    ws_out_dir = os.path.join(output_dir, TMP_WS_EXTR_DIR)
    if performance_mode:
        logger.info("going to extract sessions with tshark")
    else:
        logger.info("Going to verify results against Wireshark/tshark")
    if os.path.exists(tcpsession_out_dir):
        shutil.rmtree(tcpsession_out_dir)
    os.makedirs(tcpsession_out_dir)
    if os.path.exists(ws_out_dir):
        shutil.rmtree(ws_out_dir)
    os.makedirs(ws_out_dir)
    net_tuples = extract_data_with_tcpsessions(pcap, tcpsession_out_dir).sessions.keys()
    start_time = datetime.now()
    logger.info("Extraction with TCPSession is done. Going to verify the results against Wireshark")
    for net_tuple in net_tuples:
        tuple_filter = '(ip.src == {} && tcp.srcport == {} && ip.dst == {} && tcp.dstport == {})'
        client_filter = tuple_filter.format(net_tuple.get_str_sip(), net_tuple.sp, net_tuple.get_str_dip(),
                                            net_tuple.dp)
        server_filter = tuple_filter.format(net_tuple.get_str_dip(), net_tuple.dp, net_tuple.get_str_sip(),
                                            net_tuple.sp)
        extract_streams_cmd = 'tshark -r {} -Y "{} || {}" -T fields -e tcp.stream | sort -n -u'.format(
            pcap, client_filter, server_filter)
        logger.info("Command to extract session ids: {}".format(extract_streams_cmd))
        ws_out_file = "{}/{}".format(ws_out_dir,net_tuple)

        def tshark_session_output_verification(cmd: str, sip: str, dip: str, sport: int, dport: int, out_file: str,
                                               stream: int, count: int):
            """Parses the output of tshark command used to extract a specific session id and compares it against the
            TCPSessions's output. If there is an error it dumps the tshark extracted data in JSON file whose schema is
            defined in data/output_schema.json. Verification is done by calculation the MD5 of the data extracted from
            both the techniques, extracted data is in order it was sent from client and server, and comparing the MD5s.
            :param cmd: tshark command to extract the data a session id data
            :param sip: source IP
            :param dip: destination IP
            :param sport: source port
            :param dport: destination port
            :param out_file: output file to write the tshark/Wireshark results if extracted session data doesn't match
            :param stream: stream id for current network tuple
            :param count: count to differentiate the name of output files if there multiple sessions of a network tuple
            :return: None
            """
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True) as proc:
                if proc.returncode is not None:
                    logger.info("tshark command failed with return code {}".format(proc.returncode))
                    return
                pcap_data = False
                tcp_payload_hex = list()
                session_digester = md5()
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    if not pcap_data:
                        if line[:7] == b"Node 1:":
                            pcap_data = True
                    else:
                        if line[:3] == b'===':
                            break
                        if line[0] == 0x09:
                            line = line[1:-1]
                            pkt_src = dip
                        else:
                            pkt_src = sip
                            line = line[:-1]
                        tcp_payload_hex.append((pkt_src, line.decode("utf-8", "backslashreplace")))
                        if not performance_mode:
                            session_digester.update(line)
                hex_session_digest = session_digester.hexdigest()

                def dump_output(out_file, count):
                    out_file = "{}-{}.json".format(out_file, count)
                    logger.info("Dumping the Wireshark result in file: {}".format(out_file))
                    with open(out_file, "w") as json_fp:
                        output_dict = dict()
                        output_dict["sip"] = sip
                        output_dict["dip"] = dip
                        output_dict["sport"] = sport
                        output_dict["dport"] = dport
                        output_dict["proto"] = 6
                        output_dict["tcp_payload_hex"] = tcp_payload_hex
                        output_dict["tcp_ordered_hex_payload_md5sum"] = hex_session_digest
                        json.dump(output_dict, json_fp, indent=1)
                if performance_mode:
                    dump_output(out_file, count)
                else:
                    tcpsession_json = os.path.join(tcpsession_out_dir,
                                                   repr(net_tuple) + '-' + str(count) + ".json")
                    with open(tcpsession_json) as tcpsession_json_fp:
                        tcpsession_json_obj = json.load(tcpsession_json_fp)
                        if tcpsession_json_obj["tcp_ordered_hex_payload_md5sum"] == hex_session_digest:
                            logger.info("For pcap {} correct checksum for network tuple: "
                                        "{}, count: {}, and stream: {}".format(pcap, net_tuple, count, stream))
                        else:
                            logger.info("For pcap {} wrong checksum for network tuple: "
                                        "{}, count: {}, and stream: {}".format(pcap, net_tuple, count, stream))
                            dump_output(out_file, count)

        def extract_session_ids():
            """Extracts the distinct session id in a pcap using tshark command and call the
            tshark_session_output_verification() function for each session id for verification.
            :return: None
            """
            with subprocess.Popen(extract_streams_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  shell=True) as proc:
                streams = set()
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    streams.add(int(line))
            streams = list(streams)
            streams = sorted(streams)
            count = 0
            while True:
                if len(streams) == 0:
                    break
                stream = streams.pop()
                extract_session_data_cmd = 'tshark -r {} -q -z "follow,tcp,raw,{}"'.format(
                    pcap, stream)
                logger.info("Command to extract session# {} data: {}".format(stream, extract_session_data_cmd))
                tshark_session_output_verification(extract_session_data_cmd, net_tuple.get_str_sip(),
                                                   net_tuple.get_str_dip(), net_tuple.sp, net_tuple.dp,
                                                   ws_out_file, stream, count)
                count += 1
        extract_session_ids()
        def performance_analysis():
            """Performance analysis of different ways of extraction sessions in pcap"""
            num_op = 5
            session_data_cmd = 'for stream in `{}`; do tshark -r {}  -q -Y "{} || {}" -z "follow,tcp,raw,$stream" >' \
                               ' {}-$stream.data;done'.format(extract_streams_cmd, pcap, client_filter, server_filter,
                                                              ws_out_file)
            stmt = "{}({})".format("run_command", "session_data_cmd")
            tot = timeit.timeit(stmt=stmt,globals=locals(),number=num_op)
            print("total time take for first way: {}, per command: {}".format(tot, tot/num_op))
            session_data_cmd = 'for stream in `{}`; do tshark -r {}  -q -z "follow,tcp,raw,$stream" >' \
                               ' {}-$stream.data;done'.format(extract_streams_cmd, pcap,
                                                              ws_out_file + "type-3")
            stmt = "{}({})".format("run_command", "session_data_cmd")
            tot = timeit.timeit(stmt=stmt,globals=locals(),number=num_op)
            print("total time take for second way: {}, per command: {}".format(tot, tot/num_op))
            print(session_data_cmd)
            stmt = "{}()".format("extract_session_ids")
            tot = timeit.timeit(stmt=stmt,globals=locals(),number=num_op)
            print("total time take for current used way: {}, per command: {}".format(tot, tot/num_op))
    logger.info("Total time taken for Wireshark verification is: {}".format(datetime.now() - start_time))


def extract_js_with_bash_cmd():
    start_time = datetime.now()
    cmd = 'for var in `grep -r -l -E "(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) .+ HTTP/" .`; do' \
          ' grep -l "<script" $var ;done | wc -l'
    logger.info("Bash JS extraction command: " + cmd)
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    if output.returncode is not 0:
        logger.info("command failed with return code {}".format(output.returncode))
    logger.info(output.stdout)
    logger.info("total time take with grep : {}".format(datetime.now() - start_time))


def extract_js_with_python(input_dir, output_dir):
    import re
    start_time = datetime.now()
    #http_pattern = re.compile(r"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) .+ HTTP/.*Content-Type: text/html")
    #http_pattern = re.compile(r"(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) .+ HTTP/")
    #http_pattern = re.compile(r'"HTTP/[0-1]\.[0-9] 200 OK\\r\\n')
    http_pattern = re.compile(r'Content-Type: text/html')
    pattern = re.compile(r"(?<=<script>).*?(?=</script>|$)", re.DOTALL)

    file_count = 0
    non_http_file = 0
    without_script = 0
    with_script = 0
    for path, _dir, files in os.walk(input_dir):
        for _file in files:
            _file = os.path.join(path, _file)
            if not os.path.splitext(_file)[1] == ".json":
                continue
            with open(_file) as fp:
                dict_object = json.load(fp)
            content = [dict_object["combined_src_payload"], dict_object["combined_dst_payload"]]
            script_found = False
            http_file = False
            js_fp = None
            for value in content:
                res = http_pattern.findall(value)
                if res:
                    http_file = True
                    res = pattern.findall(value)
                    if res:
                        script_found = True
                        js_file_name = os.path.splitext(os.path.basename(_file))[0] + ".js"
                        if js_fp is None:
                            js_fp = open(os.path.join(output_dir, js_file_name), "w")
                        for _res in res:
                            js_fp.write(_res + "\n")
            file_count += 1
            if not http_file:
                non_http_file += 1
            if script_found:
                with_script += 1
            else:
                without_script += 1
    logger.info("total file: {}, non http file: {}, without script: {}, "
                "with script: {}".format(file_count, non_http_file, without_script, with_script))
    logger.info("time taken by python in extracting JS is : {}".format(datetime.now() - start_time))
    return with_script


def extract_tcpsessions_from_pcaps(_input, output_dir, tar_output_prefix=None, extract_js=False, _create_tar=False,
                                   recursive=False):
    pwd = os.getcwd()
    pcap_list = list()
    start = datetime.now()
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(_input):
        input_dir = os.path.dirname(os.path.abspath(_input))
        pcap_list = [os.path.basename(_input)]
    else:
        input_dir = os.path.abspath(_input)
        os.chdir(input_dir)
        if recursive:
            for path, dirs, files in os.walk("."):
                for _file in files:
                    if os.path.splitext(_file)[1] == ".pcap":
                        pcap_list.append(os.path.join(path, _file))
        else:
            for _file in os.listdir(input_dir):
                if os.path.isfile(_file) and os.path.splitext(_file)[1] == ".pcap":
                    pcap_list.append(_file)
    js_file_count = 0
    js_tars = list()
    json_tars = list()
    for pcap in pcap_list:
        os.chdir(input_dir)
        dir_name = os.path.dirname(pcap).strip("./")
        _file = os.path.basename(pcap)
        _file_without_ext = os.path.splitext(os.path.basename(pcap))[0]
        json_tar_output_name = dir_name.strip("./").replace("/", "_") + "_" + _file_without_ext + "-session-JSON.tar"
        tcpsession_out_dir = os.path.join(output_dir, TMP_TCPSESSION_EXTR_DIR, dir_name, _file_without_ext)
        json_tar_output_file_path = os.path.join(output_dir, TMP_TCPSESSION_EXTR_DIR, dir_name, json_tar_output_name)
        json_tars.append(json_tar_output_file_path)
        if os.path.exists(json_tar_output_file_path):
            logger.info("JSON tar {} already exists, skipping pcap {}".format(json_tar_output_file_path, pcap))
        else:
            if os.path.exists(tcpsession_out_dir):
                shutil.rmtree(tcpsession_out_dir)
            os.makedirs(tcpsession_out_dir)
            tcpflow_out_dir = os.path.join(output_dir, TMP_TCPFLOW_EXTR_DIR, dir_name)
            if os.path.exists(tcpflow_out_dir):
                shutil.rmtree(tcpflow_out_dir)
            os.makedirs(tcpflow_out_dir)
            logger.info("Going to work on pcap: {}".format(pcap))
            verify_data_with_tcpflow(pcap, tcpsession_out_dir, tcpflow_out_dir)
            logger.info("Done with pcap: {}".format(pcap))
            if _create_tar:
                os.chdir(tcpsession_out_dir)
                create_tar(os.curdir, json_tar_output_file_path)
                os.chdir(input_dir)
        if extract_js:
            js_tar_output_name = dir_name.strip("./").replace("/", "_") + _file_without_ext + "-JS.tar"
            js_output_dir = os.path.join(output_dir, TMP_JS_EXTR_DIR, dir_name, _file_without_ext)
            js_tar_output_file_path = os.path.join(output_dir, TMP_JS_EXTR_DIR, dir_name, js_tar_output_name)
            js_tars.append(js_tar_output_file_path)
            if os.path.exists(js_tar_output_file_path):
                logger.info("JS tar {} already exits, skipping pcap {}".format(js_tar_output_file_path, pcap))
            else:
                logger.info("Going to extract JS files")
                if not os.path.exists(js_output_dir):
                    os.makedirs(js_output_dir)
                else:
                    shutil.rmtree(js_output_dir)
                    os.mkdir(js_output_dir)
                js_file_count += extract_js_with_python(tcpsession_out_dir, js_output_dir)
                logger.info("Total script files found so far {}".format(js_file_count))
                if _create_tar:
                    os.chdir(js_output_dir)
                    create_tar(os.curdir, js_tar_output_file_path)
                    os.chdir(input_dir)
    logger.info("JSON of sessions are stored in {}".format(os.path.join(output_dir, TMP_TCPSESSION_EXTR_DIR)))
    if extract_js:
        logger.info("Extracted JS from the sessions are store in {}".format(os.path.join(output_dir,
                                                                                         TMP_JS_EXTR_DIR)))
    os.chdir(output_dir)
    if _create_tar:
        if extract_js:
            final_JS_tar_output_file = os.path.join(output_dir, "{}-JS.tar.gz".format(tar_output_prefix))
            logger.info("Going to create the final JS tar {}".format(final_JS_tar_output_file))
            #js_tars = os.listdir()
            logger.info("JS tar going to be added to final tar.gz: {}".format(js_tars))
            with tarfile.open(final_JS_tar_output_file, "w:gz") as final_tar_output_fp:
                for js_tar in js_tars:
                    final_tar_output_fp.add(js_tar, arcname=os.path.basename(js_tar))
            logger.info("Final JS tar created at {}!".format(final_JS_tar_output_file))
            logger.info("Total file with js script found is: {}".format(js_file_count))
        final_json_tar_output_file = os.path.join(output_dir, "{}-session-JSON.tar.gz".format(tar_output_prefix))
        logger.info("Going to create the final tar of session's JSON data {}".format(final_json_tar_output_file))
        logger.info("JSON tar going to be added to the final tar.gz: {}".format(json_tars))
        with tarfile.open(final_json_tar_output_file, "w:gz") as final_tar_output_fp:
            for json_tar in json_tars:
                final_tar_output_fp.add(json_tar, arcname=os.path.basename(json_tar))
            logger.info("Final tar of session JSON data created at {}!".format(final_json_tar_output_file))
    os.chdir(pwd)
    logger.info("Total time taken in {} is {}".format(extract_tcpsessions_from_pcaps.__name__, datetime.now() - start))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract JS from pcaps stored in directory using TCPSessions library, "
                                                 "and many other stuff. If a directory of pcaps is provided then a tar"
                                                 " of all the extracted JS could also be created.")
    parser.add_argument("-i", "--input-dir", action="store", type=str,
                        help="Directory to pick input pcaps from, picks only in the directory not recursively.")
    parser.add_argument("-o", "--output-dir", action="store", type=str,
                        help="Directory where all the output will be stored")
    parser.add_argument("-p", "--pcap", action="store", type=str, help="Input pcap.")
    parser.add_argument("-t", "--tar-output-prefix", action="store_true", help="Prefix for the name of output tar.")
    parser.add_argument("-n", "--no-js-extraction", action="store_true",
                        help="Don't extract JS from from the extracted TCP sessions. "
                        "Final tar output will be of JSON of individual sessions if input"
                        " is directory, else just JSON of individual sessions in input pcap")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Input given is directory and try to find pcaps recursively in it")
    parser.add_argument("-c", "--create-tar", action="store_true", help="Create a tar of the final output")
    parser.add_argument("-w", "--wireshark-verification", action="store_true",
                        help="Verify the output of a session extracted with TCPSession against the tshark (Wireshark)."
                             " This is a standalone option to re-verify the results of TCPSession which failed against "
                             "tcpflow command in normal usecases. "
                             "Provide the pcap as an input along with this switch to see the results.")
    parser.add_argument("-k", "--performance-comparison", action="store", type=int,
                        help="does performance comparision between TCPsession and tcpflow or Wireshark")
    args = parser.parse_args()
    recursive = False
    if args.no_js_extraction:
        extract_js = False
    else:
        extract_js = True
    if not args.input_dir:
        if not args.pcap:
            logger.info("See the help for valid arguments")
            exit(0)
        else:
            _input = args.pcap
    else:
        if not args.input_dir:
            logger.info("provide an input directory to work on")
            exit(0)
        else:
            _input = args.input_dir
            if not os.path.isdir(_input):
                logger.info("provide a valid input directory to work on")
                exit(0)
    if args.output_dir:
        output_dir = args.output_dir
        if not os.path.isdir(output_dir):
            logger.info("Provided output path is not a directory, current directory will be used for output")
            output_dir = os.path.abspath(os.curdir)
        else:
            recursive = args.recursive
    else:
        logger.info("Output directory is not provided. Extracted output will be stored in current directory")
        output_dir = os.path.abspath(os.curdir)
    if args.create_tar:
        _create_tar=args.create_tar
        if args.tar_output_prefix:
            tar_output_prefix = args.tar_output_prefix
        elif args.input_dir:
            tar_output_prefix = "extracted-session-data-"
            logger.info("No tar output file name was given.")
            logger.info("Name of the final tar would start with [your-pcap-file-name]-{}".format(tar_output_prefix))
        else:
            tar_output_prefix = "extracted-"
    else:
        _create_tar = False
        tar_output_prefix = None

    if args.wireshark_verification and args.performance_comparison:
        logger.error("Wireshark verification option is not valid with performance comparision")
        exit(0)
    else:
        if args.input_dir or args.recursive or args.create_tar or args.no_js_extraction or args.tar_output_prefix:
            if args.wireshark_verification:
                logger.info("Ignoring arguments irrelevant to wireshark verification")
            elif args.performance_comparison:
                logger.info("Ignoring arguments irrelevant to performance comparision")

    if args.wireshark_verification and args.pcap and output_dir:
        verify_data_with_wireshark(_input, output_dir)
        exit(0)
    if args.performance_comparison:
        iter_count = args.performance_comparison
        logger.info("Performance comparision using the pcap {} for {} iterations".format(_input, iter_count))
        func_name = "verify_data_with_wireshark"
        stmt = '{}("{}", "{}", {})'.format(func_name, _input, output_dir, True)
        ws_total_time = timeit.timeit(stmt=stmt, globals=globals(), number=iter_count)
        logger.info("Total time taken by {} for {} iterations is {}, per iteration"
                    " time is {}".format(func_name, iter_count, ws_total_time, ws_total_time/iter_count))
        func_name = "verify_data_with_tcpflow"
        stmt = '{}("{}", "{}", "{}")'.format(func_name, _input, os.path.join(output_dir, "tcpsession"),
                                             os.path.join(output_dir, "tcpflow"))
        ts_total_time = timeit.timeit(stmt=stmt, globals=globals(), number=iter_count)
        logger.info("Total time taken by {} for {} iterations is {}, per iteration"
                    " time is {}".format(func_name, iter_count, ts_total_time, ts_total_time/iter_count))
        logger.info("Time taken by {} is {} times of {}.".format("verify_data_with_wireshark",
                                                                 ws_total_time/ts_total_time, func_name))
        exit(0)
    extract_tcpsessions_from_pcaps(_input, output_dir, tar_output_prefix, extract_js, _create_tar, recursive)
