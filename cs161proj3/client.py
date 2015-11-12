#!/usr/bin/env python3

import getopt
import os
import select
import socket
import ssl
import struct
import sys

def usage(f=sys.stdout):
    f.write("""\
Usage: %s --tls-trustfile=FILENAME HOST PORT

  --disable-tls             run without TLS
  --socks-port=PORT         use the SOCKS proxy at 127.0.0.1:PORT
  --tls-trustfile=FILENAME  trust the root certificates in FILENAME
  --help                    show this help
""" % sys.argv[0])

class options(object):
    use_tls = True
    socks_port = None
    tls_trust_filename = None

# Return a socket connected to remote_address, which is a (hostname, port)
# tuple.
# jk: remote_hostname = 127.0.0.1 
# jk: remote_port = 5280
def connect(remote_address):
    s = socket.socket(socket.AF_INET)
    s.connect(remote_address)
    return s

# Return a socket connected to remote_address through the SOCKS4a proxy at
# socks_address.

# jk: argument = 
# jk: (hostname = yoursite.onion, remote_port = 5280), ("127.0.0.1", options.socks_port = 9150)
def connect_with_socks(remote_address, socks_address):
    hostname, port = remote_address
    # TODO
    s = socket.socket(socket.AF_INET)

    request = struct.pack("cchihh32s", "4", "2", port, 1, )

    s.connect(remote_address)
    return s    
    raise NotImplementedError("connect_with_socks not implemented")

# Parse command line options.
opts, args = getopt.gnu_getopt(sys.argv[1:], "",
    ["disable-tls", "socks-port=", "tls-trustfile=", "help"])
print ("opts: " + str(opts))  # jk: print to see
print ("args: " + str(args))
for o, a in opts:
    if o == "--disable-tls":
        options.use_tls = False
    elif o == "--socks-port":
        options.socks_port = int(a)
        print ("options.socks_port: " + str(options.socks_port))  # jk: print to see

    elif o == "--tls-trustfile":
        options.tls_trust_filename = a
    elif o == "--help":
        usage()
        sys.exit()

try:
    remote_hostname, remote_port = args
    remote_port = int(remote_port)

except ValueError:
    usage(sys.stderr)
    sys.exit(1)

print("connecting", file=sys.stderr)
try:
    if options.socks_port is not None:
        remote_socket = connect_with_socks((remote_hostname, remote_port), ("127.0.0.1", options.socks_port))
    else:
        remote_socket = connect((remote_hostname, remote_port))
except socket.error as e:
    print("cannot connect to %s port %d: %s" % (remote_hostname, remote_port, e), file=sys.stderr)
    sys.exit(1)
print("connected", file=sys.stderr)

if options.use_tls:
    # TODO
    # Wrap remote_socket in TLS and assign the resulting socket.SSLSocket back
    # to the remote_socket variable.
    raise NotImplementedError("TLS mode not implemented")

# Unbuffer stdin, change to binary mode.
sys.stdin = os.fdopen(sys.stdin.fileno(), "rb", 0)
# Change stdout to binary mode.
sys.stdout = os.fdopen(sys.stdout.fileno(), "wb")

sendbuf = []
while True:
    # select.select will notify us which file handles are ready to read.
    rset, _, _ = select.select([sys.stdin, remote_socket], [], [])
    for s in rset:
        if s == sys.stdin:
            c = s.read(1)
            if not c:
                sys.exit()
            # Buffer keyboard input until a newline.
            sendbuf.append(c)
            if c == b"\n":
                data = b"".join(sendbuf)
                remote_socket.sendall(data)
                sendbuf = []
        else:
            try:
                data = s.recv(1024)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            except socket.error:
                data = None
            if not data:
                sys.exit()
            sys.stdout.write(data)
            sys.stdout.flush()
