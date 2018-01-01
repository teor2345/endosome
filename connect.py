# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# TCP and SSL connection functions

import socket
import ssl

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

def ssl_write(context, request_bytes):
    '''
    Send a SSL request to the ssl_socket in context.
    '''
    context = get_connect_context(context)
    context['ssl_socket'].send(request_bytes)

def ssl_read(context):
    '''
    Reads bytes from the ssl_socket in context.
    '''
    context = get_connect_context(context)
    return bytearray(context['ssl_socket'].recv())

def ssl_close(context):
    '''
    Closes the ssl_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    context = get_connect_context(context)
    context['ssl_socket'].close()

def ssl_request(ip, port, request_bytes):
    '''
    Send an SSL request and receive its reply.
    '''

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((ip, port))
    ssl_socket = ssl.wrap_socket(my_socket)

    ssl_socket.sendall(request_bytes)
    response = ssl_socket.recv(MAX_READ_BUFFER_LEN)

    ssl_socket.close()

    return response
