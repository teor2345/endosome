# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# TCP and SSL connection functions

import socket
import ssl

import stem.socket

MAX_READ_BUFFER_LEN = 10*1024*1024

def get_connect_context(context):
    '''
    Return the connect context in context, which can be any kind of context.
    '''
    # TODO: extract connect contexts from stream contexts
    if 'link' in context:
        # Each link can have multiple circuits. Find the underlying link.
        context = context['link']
    else:
        # TCP, SSL, and link contexts are equivalent.
        # Each TCP connection has 0..1 SSL connections, which has 0..1 Tor
        # links.
        pass

    return context

def ssl_open(ip, port):
    '''
    Open a SSL connection to ip and port.
    Doesn't verify server certificates.
    Returns a context dictionary required to continue the connection:
        'ssl_socket'  : a SSL-wrapped TCP socket connected to ip and port
        'tcp_socket'  : a TCP socket connected to ip and port
    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''

    # TODO: verify server certificates
    ssl_socket = stem.socket.RelaySocket(ip, port)

    return {'ssl_socket' : ssl_socket}

def ssl_write(context, request_bytes):
    '''
    Send a SSL request to the ssl_socket in context.
    '''
    context = get_connect_context(context)
    context['ssl_socket'].send(request_bytes)

def ssl_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the ssl_socket in
    context.
    '''
    context = get_connect_context(context)
    return bytearray(context['ssl_socket'].recv(max_response_len))

def ssl_close(context):
    '''
    Closes the ssl_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    context = get_connect_context(context)
    context['ssl_socket'].close()

def ssl_request(ip, port, request_bytes,
                max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Send a SSL request to ip and port, and return at most max_response_len
    bytes of the response. If do_shutdown is True, shut down the socket
    immediately after reading the response.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((ip, port))
    ssl_socket = ssl.wrap_socket(my_socket)

    ssl_socket.sendall(request_bytes)
    response = ssl_socket.recv(max_response_len)

    ssl_socket.close()

    return response
