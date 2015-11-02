#!/usr/bin/env python



import sys
import struct
import socket
import time
import select
import re
import random
from collections import defaultdict
from argparse import ArgumentParser

#Some Coloring
r = '\033[31m' #red
b = '\033[34m' #blue
g = '\033[32m' #green
y = '\033[33m' #yellow
m = '\033[34m' #magenta
c = '\033[36m' #cyan

# Recognized STARTTLS modes
starttls_modes = ["ftp", "imap", "ldap", "pop3", "smtp", "xmpp"]


# Set up REs to detect ports on IPv4 and IPv6 addresses as well as STARTTLS modes
portrangere = re.compile("^(?P<start>[\d+]*)(-(?P<end>[\d+]*))?$")
ipv4re      = re.compile("^(?P<host>[^:]*?)(:(?P<port>\d+([ ,;-]+\d+)*))?$")
ipv6re      = re.compile("^(([[](?P<bracketedhost>[\dA-Fa-f:]*?)[]])|(?P<host>[^:]*?))(:(?P<port>\d+([ ,;-]+\d+)*))?$")
starttlsre  = re.compile("^(?P<port>\d+)/(?P<mode>(" + ")|(".join(starttls_modes) + "))$", re.I)


# Set up dicts to store some counters and config flags
counter_nossl   = defaultdict(int)
counter_notvuln = defaultdict(int)
counter_vuln    = defaultdict(int)
starttls_modes  = defaultdict(str)


# Parse args
parser = ArgumentParser()
parser.add_argument("-c", "--concise",    dest="concise",   default=None,                 action="store_true",  help="make output concise")
parser.add_argument("-4", "--ipv4",       dest="ipv4",      default=True,                 action="store_true",  help="turn on IPv4 scans (default)")
parser.add_argument("-6", "--ipv6",       dest="ipv6",      default=True,                 action="store_true",  help="turn on IPv6 scans (default)")
parser.add_argument(      "--no-ipv4",    dest="ipv4",                                    action="store_false", help="turn off IPv4 scans")
parser.add_argument(      "--no-ipv6",    dest="ipv6",                                    action="store_false", help="turn off IPv6 scans")
parser.add_argument(      "--no-summary", dest="summary",   default=True,                 action="store_false", help="suppress scan summary")
parser.add_argument("-t", "--timestamp",  dest="timestamp", const="%Y-%m-%dT%H:%M:%S%z:", nargs="?",            help="add timestamps to output; optionally takes format string (default: '%%Y-%%m-%%dT%%H:%%M:%%S%%z:')")
parser.add_argument("-T", "--timeout",    dest="timeout",   default=5,                                          help="set the networking timeout (default: 5)")
parser.add_argument(      "--starttls",   dest="starttls",  const="25/smtp, 110/pop3, 143/imap, 389/ldap, 5222/xmpp, 5269/xmpp", default ="", nargs="?", help="insert proper protocol stanzas to initiate STARTTLS (default: '25/smtp, 110/pop3, 143/imap, 389/ldap, 5222/xmpp, 5269/xmpp')")
parser.add_argument("-p", "--ports",      dest="ports",     action="append",              nargs=1,              help="list of ports to be scanned (default: 443)")
parser.add_argument("-l", "--length",     dest="length",    default=0x4000,               type=int,             help="heartbeat request length field")
parser.add_argument("-H", "--hosts",      dest="hosts",     default=False,                action="store_true",  help="turn off hostlist processing, process host names directly instead")
parser.add_argument("hostlist",                             default=["-"],                nargs="*",            help="list(s) of hosts to be scanned (default: stdin)")
args = parser.parse_args()


# Function to encapsulate port list specification parsing
def parse_portlist(inputlist):
    finallist = []
    tmplist = []
    for port in inputlist:
        tmplist.extend(port[0].replace(",", " ").replace(";", " ").split())
    for port in tmplist:
        match = portrangere.match(str(port))
        if not match:
            sys.exit("ERROR: Invalid port specification: " + port)
        if match.group("end"):
            finallist.extend(range(int(match.group("start")), int(match.group("end")) + 1))
        else:
            finallist.append(int(match.group("start")))
    return sorted(list(set([i for i in finallist])))


# Parse port list specification
if not args.ports:
    args.ports = [["443"]]
portlist = parse_portlist(args.ports)


# Parse STARTTLS mode specification
tmplist = args.starttls.replace(",", " ").replace(";", " ").split()
for starttls in tmplist:
    match = starttlsre.match(starttls)
    if not match:
        sys.exit("ERROR: Invalid STARTTLS specification: " + starttls)
    starttls_modes[int(match.group("port"))] = match.group("mode").lower()


# Define nice xstr function that converts None to ""
xstr = lambda s: s or ""


def get_ipv4_address(host):
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET, 0, socket.SOL_TCP)
    except socket.error:  # not a valid address
        return False
    return address[0][4][0]


def get_ipv6_address(host):
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET6, 0, socket.SOL_TCP)
    except socket.error:  # not a valid address
        return False
    return address[0][4][0]


def h2bin(x):
    x = re.sub(r'#.*$', r'', x, flags=re.MULTILINE)
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello_pre = h2bin('''
        16          # type
        03 00       # version
        02 f2       # len
        01          # type
        00 02 ee    # len
        03 00       # version
        ''')

hello_post = h2bin('''
        # session id
        00          # len

        # cipher suites
        02 7c       # len   636 = 318 suites
        00 00
        00 01
        00 02
        00 03
        00 04
        00 05
        00 06
        00 07
        00 08
        00 09
        00 0a
        00 0b
        00 0c
        00 0d
        00 0e
        00 0f
        00 10
        00 11
        00 12
        00 13
        00 14
        00 15
        00 16
        00 17
        00 18
        00 19
        00 1a
        00 1b
        00 1e
        00 1f
        00 20
        00 21
        00 22
        00 23
        00 24
        00 25
        00 26
        00 27
        00 28
        00 29
        00 2a
        00 2b
        00 2c
        00 2d
        00 2e
        00 2f
        00 30
        00 31
        00 32
        00 33
        00 34
        00 35
        00 36
        00 37
        00 38
        00 39
        00 3a
        00 3b
        00 3c
        00 3d
        00 3e
        00 3f
        00 40
        00 41
        00 42
        00 43
        00 44
        00 45
        00 46
        00 67
        00 68
        00 69
        00 6a
        00 6b
        00 6c
        00 6d
        00 84
        00 85
        00 86
        00 87
        00 88
        00 89
        00 8a
        00 8b
        00 8c
        00 8d
        00 8e
        00 8f
        00 90
        00 91
        00 92
        00 93
        00 94
        00 95
        00 96
        00 97
        00 98
        00 99
        00 9a
        00 9b
        00 9c
        00 9d
        00 9e
        00 9f
        00 a0
        00 a1
        00 a2
        00 a3
        00 a4
        00 a5
        00 a6
        00 a7
        00 a8
        00 a9
        00 aa
        00 ab
        00 ac
        00 ad
        00 ae
        00 af
        00 b0
        00 b1
        00 b2
        00 b3
        00 b4
        00 b5
        00 b6
        00 b7
        00 b8
        00 b9
        00 ba
        00 bb
        00 bc
        00 bd
        00 be
        00 bf
        00 c0
        00 c1
        00 c2
        00 c3
        00 c4
        00 c5
        00 ff
        c0 01
        c0 02
        c0 03
        c0 04
        c0 05
        c0 06
        c0 07
        c0 08
        c0 09
        c0 0a
        c0 0b
        c0 0c
        c0 0d
        c0 0e
        c0 0f
        c0 10
        c0 11
        c0 12
        c0 13
        c0 14
        c0 15
        c0 16
        c0 17
        c0 18
        c0 19
        c0 1a
        c0 1b
        c0 1c
        c0 1d
        c0 1e
        c0 1f
        c0 20
        c0 21
        c0 22
        c0 23
        c0 24
        c0 25
        c0 26
        c0 27
        c0 28
        c0 29
        c0 2a
        c0 2b
        c0 2c
        c0 2d
        c0 2e
        c0 2f
        c0 30
        c0 31
        c0 32
        c0 33
        c0 34
        c0 35
        c0 36
        c0 37
        c0 38
        c0 39
        c0 3a
        c0 3b
        c0 3c
        c0 3d
        c0 3e
        c0 3f
        c0 40
        c0 41
        c0 42
        c0 43
        c0 44
        c0 45
        c0 46
        c0 47
        c0 48
        c0 49
        c0 4a
        c0 4b
        c0 4c
        c0 4d
        c0 4e
        c0 4f
        c0 50
        c0 51
        c0 52
        c0 53
        c0 54
        c0 55
        c0 56
        c0 57
        c0 58
        c0 59
        c0 5a
        c0 5b
        c0 5c
        c0 5d
        c0 5e
        c0 5f
        c0 60
        c0 61
        c0 62
        c0 63
        c0 64
        c0 65
        c0 66
        c0 67
        c0 68
        c0 69
        c0 6a
        c0 6b
        c0 6c
        c0 6d
        c0 6e
        c0 6f
        c0 70
        c0 71
        c0 72
        c0 73
        c0 74
        c0 75
        c0 76
        c0 77
        c0 78
        c0 79
        c0 7a
        c0 7b
        c0 7c
        c0 7d
        c0 7e
        c0 7f
        c0 80
        c0 81
        c0 82
        c0 83
        c0 84
        c0 85
        c0 86
        c0 87
        c0 88
        c0 89
        c0 8a
        c0 8b
        c0 8c
        c0 8d
        c0 8e
        c0 8f
        c0 90
        c0 91
        c0 92
        c0 93
        c0 94
        c0 95
        c0 96
        c0 97
        c0 98
        c0 99
        c0 9a
        c0 9b
        c0 9c
        c0 9d
        c0 9e
        c0 9f
        c0 a0
        c0 a1
        c0 a2
        c0 a3
        c0 a4
        c0 a5
        c0 a6
        c0 a7
        c0 a8
        c0 a9
        c0 aa
        c0 ab
        c0 ac
        c0 ad
        c0 ae
        c0 af

        # compressors
        01          # len
        00

        # extensions
        00 49       # len

        # ext: ec point formats
        00 0b       # type
        00 04       # len
        03          # len
        00
        01
        02

        # ext: elliptic curves
        00 0a       # type
        00 34       # len
        00 32       # len
        00 0e
        00 0d
        00 19
        00 0b
        00 0c
        00 18
        00 09
        00 0a
        00 16
        00 17
        00 08
        00 06
        00 07
        00 14
        00 15
        00 04
        00 05
        00 12
        00 13
        00 01
        00 02
        00 03
        00 0f
        00 10
        00 11

        # ext: session ticket
        00 23       # type
        00 00       # len

        # ext: heartbeat
        00 0f       # type
        00 01       # len
        01          # peer_allowed_to_send
        ''')

def create_clienthello():
    return  hello_pre + \
            struct.pack('>L', time.time()) + \
            struct.pack('>7L',              random.getrandbits(32),
                    random.getrandbits(32), random.getrandbits(32),
                    random.getrandbits(32), random.getrandbits(32),
                    random.getrandbits(32), random.getrandbits(32)) + \
            hello_post

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        #print '  %04x: %-48s %s' % (b, hxdat, pdat)
    #print

recv_buffer = ''

def recvall(s, length, timeout=5):
    global recv_buffer
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        if len(recv_buffer)>0:
            d = recv_buffer[:remain]
            remain -= len(d)
            rdata += d
            recv_buffer = recv_buffer[len(d):]
        if remain==0:
            return rdata
        rtime = endtime - time.time()
        if rtime < 0:
            if len(rdata)>0:
                return rdata
            else:
                return None
        r, w, e = select.select([s], [], [], 1)
        if s in r:
	    try:
                data = s.recv(remain)
	    except Exception, e:  # Problem while receiving
                if len(rdata) > 0:
                    return rdata
                else:
                    return None

            # EOF?
            if not data:
                if len(rdata)>0:
                    return rdata
                else:
                    return None
            recv_buffer += data
    return rdata

def do_starttls(s, mode):
    if mode == "smtp":
        # receive greeting
        recvall(s, 1024)
        # send EHLO
        s.send("EHLO poodle-sniffer.example.com\r\n")
        # receive capabilities
        cap = recvall(s, 1024)
        #print cap
        if 'STARTTLS' in cap:
            # start STARTTLS
            s.send("STARTTLS\r\n")
            ack = recvall(s, 1024)
            if "220" in ack:
                return True
#    elif mode == "imap":
#        # receive greeting
#        s.recv(1024)
#        # start STARTTLS
#        s.send("a001 STARTTLS\r\n")
#        # receive confirmation
#        if "a001 OK" in s.recv(1024):
#            return True
#        else:
#            return False
#    elif mode == "pop3":
#        # receive greeting
#        s.recv(1024)
#        # STARTTLS 
#        s.send("STLS\r\n")
#        if "+OK" in s.recv(1024):
#            return True
#        else:
#            return False
    return False

def parse_handshake(buf):
    remaining = len(buf)
    skip = 0
    while remaining > 0:
        if remaining < 4:
            #print 'Length mismatch; unable to parse SSL handshake'
            return False
        typ = ord(buf[skip])
        highbyte, msglen = struct.unpack_from('>BH', buf, skip + 1)
        msglen += highbyte * 0x10000
        if typ == 14:
            #print 'server hello done'
            return True
        remaining -= (msglen + 4)
        skip += (msglen + 4)
    return False

def recv_sslrecord(s):
    hdr = recvall(s, 5, 5)
    if hdr is None:
        return None, None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        #print 'No payload received; server closed connection'
        return None, None, None, None
    if typ == 22:
        server_hello_done = parse_handshake(pay)
    else:
        server_hello_done = None
    return typ, ver, pay, server_hello_done

def is_vulnerable(domain, port, protocol):
    global recv_buffer
    recv_buffer = ''
    s = socket.socket(protocol, socket.SOCK_STREAM)
    s.settimeout(int(args.timeout))
    try:
        s.connect((domain, port))
    except Exception, e:
        return None
    if starttls_modes[port]:
        do_starttls(s, starttls_modes[port])
    s.send(create_clienthello())
    version = None
    while True:
        typ, ver, pay, done = recv_sslrecord(s)
        if typ == None:
            return None
        if typ == 21:
            return False
        if typ == 22 and done:
            return True


def scan_address(domain, address, protocol, portlist):
    if args.timestamp:
        print time.strftime(args.timestamp, time.gmtime()),
    if not args.concise:
        print b+"[+]"+y+"Testing " +c+ domain + " (" + address + ")... ",
    else:
        print domain + " (" + address + ")",

    for port in portlist:
        sys.stdout.flush();
        result = is_vulnerable(address, port, protocol);
        if result is None:
            if not args.concise:
                print "port " + str(port) + m+": no SSL/unreachable;",
            else:
                print str(port) + "-",
            counter_nossl[port] += 1;
        elif result:
            if not args.concise:
                print "port " + str(port) + r + " : VULNERABLE!",
            else:
                print str(port) + "!",
            counter_vuln[port] += 1;
        else:
            if not args.concise:
                print "port " + str(port) + g+": not vulnerable;",
            else:
                print str(port) + "+",
            counter_notvuln[port] += 1;
    print ""


def scan_host(domain):
    if args.ipv4:
        match = ipv4re.match(domain)
        if match:
            hostname = xstr(match.group("host"))
            address = get_ipv4_address(hostname)
            if address:
                if match.group("port"):
                    scan_address(hostname, address, socket.AF_INET, parse_portlist([[match.group("port")]]))
                else:
                    scan_address(hostname, address, socket.AF_INET, portlist)

    if args.ipv6:
        match = ipv6re.match(domain)
        if match:
            hostname = xstr(match.group("bracketedhost")) + xstr(match.group("host"))
            address = get_ipv6_address(hostname)
            if address:
                if match.group("port"):
                    scan_address(hostname, address, socket.AF_INET6, parse_portlist([[match.group("port")]]))
                else:
                    scan_address(hostname, address, socket.AF_INET6, portlist)


def main():
    if args.hosts:
        for input in args.hostlist:
            scan_host(input)
    else:
        for input in args.hostlist:
            if input == "-":
                for line in sys.stdin:
                    scan_host(line.strip())
            else:
                file = open(input, 'r')
                for line in file:
                    scan_host(line.strip())
                file.close()

    if args.summary:
        print
        if args.timestamp:
            print time.strftime(args.timestamp, time.gmtime()),
        print "- no SSL/unreachable: " + str(sum(counter_nossl.values())) + " (" + "; ".join(["port " + str(port) + ": " + str(counter_nossl[port]) for port in sorted(counter_nossl.keys())]) + ")"
        if args.timestamp:
            print time.strftime(args.timestamp, time.gmtime()),
        print "! VULNERABLE: " + str(sum(counter_vuln.values())) + " (" + "; ".join(["port " + str(port) + ": " + str(counter_vuln[port]) for port in sorted(counter_vuln.keys())]) + ")"
        if args.timestamp:
            print time.strftime(args.timestamp, time.gmtime()),
        print "+ not vulnerable: " + str(sum(counter_notvuln.values())) + " (" + "; ".join(["port " + str(port) + ": " + str(counter_notvuln[port]) for port in sorted(counter_notvuln.keys())]) + ")"


if __name__ == '__main__':
    main()
