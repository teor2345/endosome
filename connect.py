# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# TCP and SSL connection functions

import socket
import ssl

MAX_READ_BUFFER_LEN = 10*1024*1024

def tcp_open(ip, port):
    '''
    Send a TCP request to ip and port.
    Returns a context dictionary required to continue the connection:
        'tcp_socket'  : a TCP socket connected to ip and port
    '''
    tcp_socket = socket.create_connection((ip, port))
    return {
        'tcp_socket' : tcp_socket,
        }

def tcp_write(context, request_bytes):
    '''
    Send a TCP request to the tcp_socket in context.
    '''
    context['tcp_socket'].sendall(request_bytes)

def tcp_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the tcp_socket in
    context.
    '''
    return context['tcp_socket'].recv(max_response_len)

def tcp_close(context, do_shutdown=True):
    '''
    Closes the tcp_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    if do_shutdown:
        context['tcp_socket'].shutdown(socket.SHUT_RDWR)
    context['tcp_socket'].close()

def tcp_request(ip, port, request_bytes,
                max_response_len=MAX_READ_BUFFER_LEN, do_shutdown=True):
    '''
    Send a TCP request to ip and port, and return at most max_response_len
    bytes of the response. If do_shutdown is True, shut down the socket
    immediately after reading the response.
    '''
    context = tcp_open(ip, port)
    tcp_write(context, request_bytes)
    response_bytes = tcp_read(context, max_response_len)
    tcp_close(context, do_shutdown)
    return response_bytes

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
    context = tcp_open(ip, port)
    # TODO: verify server certificates
    ssl_socket = ssl.wrap_socket(context['tcp_socket'])
    context.update({
            'ssl_socket' : ssl_socket
            })
    return context

def ssl_write(context, request_bytes):
    '''
    Send a SSL request to the ssl_socket in context.
    '''
    context['ssl_socket'].sendall(request_bytes)

def ssl_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the ssl_socket in
    context.
    '''
    return context['ssl_socket'].recv(max_response_len)

def ssl_close(context, do_shutdown=True):
    '''
    Closes the ssl_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    if do_shutdown:
        context['ssl_socket'].shutdown(socket.SHUT_RDWR)
    context['ssl_socket'].close()

def ssl_request(ip, port, request_bytes,
                max_response_len=MAX_READ_BUFFER_LEN, do_shutdown=True):
    '''
    Send a SSL request to ip and port, and return at most max_response_len
    bytes of the response. If do_shutdown is True, shut down the socket
    immediately after reading the response.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = ssl_open(ip, port)
    ssl_write(context, request_bytes)
    response_bytes = ssl_read(context, max_response_len)
    ssl_close(context, do_shutdown)
    return response_bytes
