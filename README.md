### TCPsession

TCPSession is a native Python library that extracts out session data sent over a TCP connection from both sides 
 from a pcap. It's faster than firing up `tshark -z "follow,tcp,ascii,#` or Wireshark on the pcap and doing 
 `follow TCP stream` in other words. I handles all the cases of TCP protocal, like - discarding the retransmissions,
  carrying out the assembly of segments at TCP layer, handling out-of-order
 delivery and then extracting out the data that is actually delivered to application layer by TCP layer
 on both the sides.

If we open a pcap with TCP packets in the Wireshark, and do follow stream on a TCP
session, we get actual payload delivered to the application layer; this Wireshark UI feature
is present in Wireshark command line utility (tshark) with command - 
`tshark -r your.pcap -Y "ip.host == 100.1.21.181 && tcp.port == 7201" -z "follow,tcp,ascii,1"`.
 Goal is to do this session data extraction faster than creating a tshark process to extract the payload.

Another option do this is using the binary `tcpflow`, available at https://github.com/simsong/tcpflow.
As tcpflow, is written in C++, it's faster than this library for obvious reasons - 
 Python can't match the speed of C++, but this library extracts data in more useful formats than tcpflow,
 for e.g., tcpflow only extracts data from both sides and combines them and store it in two files,
 the order in which that data was exchanged between peers is not preserved.
 This library extracts data as tcpflow, in addition it also stores the data where order of 
 transfer is maintained. Additionally, it also saves the data in both hex and ASCII format.

Before writing this library, my research to this simple (actually pretty complex) job included
 looking into tools like, `scapy`, `dpkt` and `wireshark` libraries, but none of them provided a way to 
 do the job I described earlier. `Scapy` can do it with the support of wireshark, but 
 inside the hood it fires up the tshark (or Wireshrk) binary, which is not any different than 
 what I mentioned earlier - firing wireshark binary and passing it a pcap to work on. 

When I started working on this small problem (it's not small, it's actually implementation of 
 whole TCP and IP stack but here we have pcap at our hands with data from both the side), 
 I did not realize the scope of problem that how big of a problem this is, and that's why
 I guess there is no library available in Python which does such kind of job.
 So, hopefully this library will be helpful if you are looking for something in Python.
 
 Another motivation for this project was to figure out the intricate details of TCP/IP stack and
 how to implement them. I got to know of `libnids/pynids` library after I had completed this project, it
 does what I needed in C/Python, though I have not verified it fully but from the project description
 it seems like it could do the job, one caveat for libnids is that it has not been updated since 2010.
See - https://linux.die.net/man/3/libnids and http://libnids.sourceforge.net/. Also, it's an IPS engine,
which means one needs to do plumbing around the libnids to gather data and play pcaps, which doesn't
seem like it's going to be faster because replaying a pcap will also need to spawn a process.

On correctness of this library, when I tested this project I wrote all the test cases from scratch,
 in which I tried to cover all the edge cases of TCP protocol. 
 I didn't test IP layer, because we are dealing with pcaps here
and in the end data will go to TCP layer and if it handles the data in right way,
it will be able to extract correct payload. After I found out about libnids, which lists
various test cases that needs to be handled correctly at TCP layer, see
http://libnids.sourceforge.net/TESTS, I verfied that the cases mentioned in the TCP section, 
have been covered with my test cases.
 Test case F from libnids tests is not tested, and it doesn't need to because
we have no obligation to deliver the data to application, we just need to extract it.

#### Requirements:

    Python3, pip, wireshark (tshark), and tcpflow.


##### Usage:
###### Installation:
Clone the repository then install the requirements with `pip install -r requirements.txt`. 

To install the library do `python3 setup.py install`.

If you want to use the script `tcpsessions_from_pcap.py` then you will need to install
 `wireshark` (tshark) and `tcpflow` as well.


To simply extract sessions from a pcap once `TCPSession` is in your python path:

    import TCPSessions
    pcap = "your.pcap"
    tcpsessions = TCPSessions(pcap)
    tcpsessions.process_pcap()
    tcpsessinos.dump_all_sessions("your_output_dir")

Example of usage could also be found in `tcpsessions_from_pcap.py` script, which also generates
 `tcpsessions_from_pcap.log` file. It also has option of doing performance testing. Additionally, 
 it provides an option to extract JS from TCP sessions. 

This library requires Python3.
Before using the script to extract sessions from pcap, please install the requirements with
command `pip install -r requirements.txt`. Few example of usage of the `tcpsessions_from_pcap.py`
script are following:

###### Single pcap session extraction:
  
    mkdir /tmp/tcpsessions_from_pcap && python3 tcpsessions_from_pcap.py -p data/big-920-sessions.pcap -o /tmp/tcpsessions_from_pcap

Check number of JSON file, one for each session, created:

`ls /tmp/tcpsessions_from_pcap/tcpsession/big-920-sessions/*.json | wc -l`

Open the input pcap in wireshark: `Wireshark data/big-920-sessions.pcap&`

Use the filter: `tcp.stream eq 920` should result in zero packets but 919 will give you a session,
which shows pcap has 920 sessions.

Check if our JS output is correct: `Wireshark -R 'tcp.payload matches "<script"' data/big-920-sessions.pcap`
can show different session containing JS data.

By default `tcpsessions_from_pcap.py` verifies the result against `tcpflow`, but there is also an option
to use `wireshark` to that job as well, eg below, don't wait for it to finish it because wireshark is going
to take long for 920 sessions:

    python3 tcpsessions_from_pcap.py -p data/big-920-sessions.pcap -o /tmp/tcpsessions_from_pcap -w

In some cases output would different from wireshark because it doesn't care about if there are any 
irregularity in TCP protocol, it just considers every handshake is correct and in some cases assumes it.
See e.g. below:

    python3 tcpsessions_from_pcap.py -p data/failed_200.1.71.197_80-100.1.6.66_22056.pcap -o /tmp/tcpsessions_from_pcap -w
    
To see where does output of this library didn't match against `wireshark` or `tcpflow` use:

`grep "wrong" tcpsessions_from_pcap.log`

and compare the same pcap against wireshark with command:

`Wireshark data/failed_200.1.71.197_80-100.1.6.66_22056.pcap&`, you will notice that session whose checksum
didn't match didn't have proper TCP handshake.

###### Session extraction from multiple pcaps in a directory

Use the `tcpsessions_from_pcap.py` on the directory containing files with `.pcap` extension as below, -r is for 
recursively and -c is to create tar of final output:

`python3 tcpsessions_from_pcap.py -i data/ -o /tmp/tcpsessions_from_pcap -r -c`

analyze the output with below commands:

`ls -lah /tmp/tcpsessions_from_pcap/`

`find /tmp/tcpsessions_from_pcap -name "*.js" | wc -l`

`find /tmp/tcpsessions_from_pcap -name "*.json" | wc -l`
