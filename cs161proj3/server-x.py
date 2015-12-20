#!/usr/bin/env python3

import getopt
import select
import socket
import ssl
import sys

def usage(f=sys.stdout):
    f.write("""\
Usage: %s --tls-cert=FILENAME --tls-key=FILENAME HOST PORT

  --disable-tls        run without TLS
  --tls-cert=FILENAME  use this TLS certificate (required without --disable-tls)
  --tls-key=FILENAME   use this TLS private key (required without --disable-tls)
  --help               show this help
""" % sys.argv[0])

class options(object):
    use_tls = True
    tls_cert_filename = None
    tls_key_filename = None

CLIENT_SOCKETS = set()

def socket_to_username(s):
    return "user %d" % s.fileno()

# Send msg to all connected clients.
def broadcast(msg):
    for s in tuple(CLIENT_SOCKETS):
        try:
            s.sendall(msg)
        except socket.error:
            CLIENT_SOCKETS.remove(s)

# Parse command line options.
opts, args = getopt.gnu_getopt(sys.argv[1:], "", ["disable-tls", "tls-cert=", "tls-key=", "help"])
for o, a in opts:
    if o == "--disable-tls":
        options.use_tls = False
    elif o == "--tls-cert":
        options.tls_cert_filename = a
    elif o == "--tls-key":
        options.tls_key_filename = a
    elif o == "--help":
        usage()
        sys.exit()
try:
    listen_hostname, listen_port = args
    listen_port = int(listen_port)
except ValueError:
    usage(sys.stderr)
    sys.exit(1)

if options.use_tls and (options.tls_cert_filename is None or options.tls_key_filename is None):
    print("--tls-cert and --tls-key are required unless --disable-tls is used", file=sys.stderr)
    sys.exit(1)

# Open the listening socket.
listen_socket = socket.socket(socket.AF_INET)
listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listen_socket.bind((listen_hostname, listen_port))
listen_socket.listen(0)

if options.use_tls:
    # print ("hellohellohellohellohellohellohellohellohellohellohellohellohello")
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile = options.tls_cert_filename, keyfile = options.tls_key_filename)
    context.verify_mode = ssl.CERT_NONE

    if context.verify_mode == ssl.CERT_NONE:
        print ("it is rightttttttttttttttttttttttttttttttttttttttttttttttttt")
    listen_socket = context.wrap_socket(listen_socket, server_side = True)
    print ("succeedddddddddddddddddddddddddddddddddddddddddd")
    # TODO
    # Wrap listen_socket in TLS and assign the resulting socket.SSLSocket back
    # to the listen_socket variable.
    # raise NotImplementedError("TLS mode not implemented")

while True:
    # select.select will notify us which sockets are ready to read.
    rset, _, _ = select.select([listen_socket] + list(CLIENT_SOCKETS), [], [])
    for s in rset:
        if s == listen_socket:
            # s is listen_socket, accept a connection.
            try:
                client_socket, _ = listen_socket.accept()
            except ssl.SSLError:
                continue
            CLIENT_SOCKETS.add(client_socket)
            broadcast(("*** %s entered the room.\n" % socket_to_username(client_socket)).encode())
        else:
            # s is a client socket, read and broadcast.
            try:
                data = s.recv(1024)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            except socket.error:
                data = None
            if data:
                broadcast(("<%s> " % socket_to_username(s)).encode() + data.rstrip(b"\n") + b"\n")
            else:
                CLIENT_SOCKETS.remove(s)
                broadcast(("*** %s left the room.\n" % socket_to_username(s)).encode())