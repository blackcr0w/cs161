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
def connect(remote_address):
    s = socket.socket(socket.AF_INET)
    s.connect(remote_address)
    return s



# Return a socket connected to remote_address through the SOCKS4a proxy at
# socks_address.
# remote host, remote port, localhost, tor proxy port
# '55mkdgawjdimhnkb.onion', '5280', 127.0.0.1, 9150
def connect_with_socks(remote_address, socks_address):
    hostname, port = remote_address
    hostname = str.encode(hostname)
    type(hostname)
   # print("*******  " + hostname)
    # TODO
    s = socket.socket(socket.AF_INET)
    s.connect(socks_address)
    dest_ip = int(7)  # this is to represent: cannot resolt the destIP from hostname
    # rule = 'cchIBB32sB'   dest_ip, 15, zero, hostname, zero
    zero = struct.pack('B', 0)
    rule = '!BBhIBc32s'  # Q: userID + 
    # a = struct.pack('32s', "aaa")
    packed_request = struct.pack(rule, 4, 1, port, dest_ip, 15, zero, hostname)

    print("packet request: " ,packed_request)
    s.send(packed_request)
    response = s.recv(16)
    # response = str.decode(response)
    print (response)
    return s

# Parse command line options.
opts, args = getopt.gnu_getopt(sys.argv[1:], "",
    ["disable-tls", "socks-port=", "tls-trustfile=", "help"])
for o, a in opts:
    print ("opt = " + str(opts))
    print ("args = " + str(args))
    print ("o = : " + str(o))
    print ("a = : " + str(a))

    if o == "--disable-tls":
        options.use_tls = False
    elif o == "--socks-port":
        options.socks_port = int(a)
    elif o == "--tls-trustfile":
        options.tls_trust_filename = a
    elif o == "--help":
        usage()
        sys.exit()
try:
    remote_hostname, remote_port = args  # '55mkdgawjdimhnkb.onion', '5280'
    remote_port = int(remote_port)
    print ("remote_hostname = : " + str(remote_hostname))
    print ("remote_port = : " + str(remote_port))
except ValueError:
    usage(sys.stderr)
    sys.exit(1)

print("connecting", file=sys.stderr)
try:
    if options.socks_port is not None:
        # '55mkdgawjdimhnkb.onion', '5280', 127.0.0.1, 9150
        # remote host, remote port, localhost, tor proxy port
        print ("options.socks_port: " + str(options.socks_port))
        remote_socket = connect_with_socks((remote_hostname, remote_port), ("127.0.0.1", options.socks_port))
    else:
        # remote_host = 127.0.0.1, remote_port = 5280
        remote_socket = connect((remote_hostname, remote_port))  
except socket.error as e:
    print("cannot connect to %s port %d: %s" % (remote_hostname, remote_port, e), file=sys.stderr)
    sys.exit(1)
print("connected", file=sys.stderr)



if options.use_tls:
    print("waitttttttttttttttttttttttttttttttttttttttttttt")
    ################################ step 2? #########################
    
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s = socket.socket(socket.AF_INET)

    
    # genearte a ssl socket
    # SSLContext.wrap_socket(sock, server_side=False, 
    # do_handshake_on_connect=True, suppress_ragged_eofs=True, server_hostname=None)

    #  ssl.wrap_socket(sock, keyfile=None, certfile=None, 
    # server_side=False, cert_reqs=CERT_NONE, ssl_version={see docs}, 
    # ca_certs=None, do_handshake_on_connect=True, suppress_ragged_eofs=True, ciphers=None)


    # On client connections, the optional parameter server_hostname specifies 
    # the hostname of the service which we are connecting to. 

    # This allows a single server to host multiple SSL-based services with 
    # distinct certificates, quite similarly to HTTP virtual hosts. 
    # Specifying server_hostname will raise a ValueError if server_side is true.

    # The parameter cert_reqs specifies whether a certificate is required from 
    # the other side of the connection, and whether it will be validated if provided. 
    # It must be one of the three values CERT_NONE (certificates ignored), 
    # CERT_OPTIONAL (not required, but validated if provided), or CERT_REQUIRED (required and validated). If the value of this parameter is not CERT_NONE, then the ca_certs parameter must point to a file of CA certificates.
    '''
    ssl_sock = ssl.wrap_socket(s,
                               ca_certs="my.crt",
                               cert_reqs=ssl.CERT_REQUIRED)
    '''
    # require a certificate from the server
    # enable certificate verification (CERT_REQUIRED)
 
    # context = ssl.create_default_context()
    '''
    >>> done? enable certificate verification (CERT_REQUIRED),  
    >>> done? enable checking of hostnames,   >>> SSLContext.check_hostname
    >>> wrong method? load the trusted verification certificates from options.tls_trust_filename, 
    >>> done? and pass server_hostname=remote_hostname to the wrap_socket call

    '''
    # Selects the highest protocol version that both the client and 
    # server support. Despite the name, this option can select “TLS” protocols as well as “SSL”.
    # ssl.PROTOCOL_SSLv23 same result
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(options.tls_trust_filename)
    print ("this is hostname")
    print (remote_hostname)

    remote_socket = context.wrap_socket(socket.socket(socket.AF_INET),server_side = False, server_hostname=remote_hostname)
    # remote_socket = context.wrap_socket(remote_socket,server_side = False, server_hostname=remote_hostname)

    # remote_socket = context.wrap_socket(remote_socket, server_hostname="https://www.example.com:80/")
    # print ("55555555555555555555555555555")

    # build connection conn.connect((remote_hostname, port_number))
    # fetch the cert cert = conn.getpeercert()

    # conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="www.python.org")
    # conn.connect(("https://www.example.com:80/", 80))
    # TODO
    # Wrap remote_socket in TLS and assign the resulting socket.SSLSocket back
    # to the remote_socket variable.

    # raise NotImplementedError("TLS mode=not implemented")

# Unbuffer stdin, change to binary mode.
sys.stdin = os.fdopen(sys.stdin.fileno(), "rb", 0)
# Change stdout to binary mode.
sys.stdout = os.fdopen(sys.stdout.fileno(), "wb")

sendbuf = []
while True:
    # select.select will notify us which file handles are ready to read.
    #rs, ws, es = select.select(inputs,[],[]) input, output, exception
    rset, _, _ = select.select([sys.stdin, remote_socket], [], [])
    for s in rset:
        if s == sys.stdin:
            c = s.read(1) ###?????????
            # we provided an argument of 1, which just means we want to read the next character
            if not c:
                print ("notcnotcnotcnotc")
                sys.exit()
            # Buffer keyboard input until a newline.
            sendbuf.append(c)
            if c == b"\n":
                data = b"".join(sendbuf)
                remote_socket.sendall(data)
                sendbuf = []

        # ignore else temporarily
        else:
            try:
                data = s.recv(1024)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # print ("hello1hello1hello1hello1")
                continue
            except socket.error:
                # print ("hello2hello2hello2hello2")
                data = None
            if not data:
                sys.exit()
            sys.stdout.write(data)
            sys.stdout.flush()
