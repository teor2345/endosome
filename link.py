# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Link-level functions

import binascii

import stem.client.cell
import stem.socket

from connect import *
from cell import *
from stem.client import AddrType, Address

def get_link_version(context, force_link_version=None):
    '''
    Return force_link_version, if it is not None, or the link version from
    context.
    If both are None, or context does not have a link version, return None.
    '''
    context = get_connect_context(context)
    if force_link_version is not None:
        return force_link_version
    return context.get('link_version')

def get_link_version_list(context, force_link_version=None):
    '''
    Return [force_link_version], if it is not None, or the link version list
    from context.
    If both are None, or context does not have a link version, return an empty
    list.
    '''
    context = get_connect_context(context)
    if force_link_version is not None:
        return [force_link_version]
    return context.get('link_version_list', [])

def unpack_cells_link(context, data_bytes,
                      force_link_version=None):
    '''
    Call unpack_cells() with the appropriate values from the context,
    and return its result.
    '''
    context = get_connect_context(context)
    link_version = get_link_version(context,
                                    force_link_version=force_link_version)
    link_version_list = get_link_version_list(context,
                                    force_link_version=force_link_version)
    return unpack_cells(data_bytes,
                        link_version_list=link_version_list,
                        force_link_version=link_version)

def link_open(ip, port, link_version_list=[3,4,5], send_netinfo=True):
    '''
    Open a link-level Tor connection to ip and port, using the highest
    link version in link_version_list supported by both sides.

    If send_netinfo is true, send a NETINFO cell after the link version
    is negotiated, using ip as the receiver IP address.
    NETINFO cells are required by Tor.
    See https://trac.torproject.org/projects/tor/ticket/22951

    Returns a context dictionary required to continue the connection:
        'link_version'             : the Tor cell link version used on the link
        'link_version_list'        : the list sent in the link VERSIONS cell
        'ssl_socket'               : a SSL-wrapped TCP socket connected to ip
                                    and port

    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''

    conn = stem.socket.RelaySocket(ip, port)
    conn.send(stem.client.cell.VersionsCell.pack(link_version_list))

    # From the VERSIONS reply determine the highest protocol version we both
    # support. Following cells are ignored since we don't use them.

    versions_reply, _ = stem.client.cell.Cell.unpack(conn.recv(), 2)
    link_version = get_highest_common_version(versions_reply.versions, link_version_list)

    # Now we know the link version, send a netinfo cell

    if send_netinfo:
        conn.send(stem.client.cell.NetinfoCell.pack(link_version, Address(AddrType.IPv4, ip), []))

    return {
      'ssl_socket': conn,
      'link_version': link_version,
      'link_version_list': link_version_list,
    }

def link_pack_cell(context,
                   cell,
                   force_link_version=None):
    '''
    Pack the Tor cell specified by cell using the link_version in context.
    force_link_version overrides the link_version in context.
    The dict cell can have the following elements:
        cell_command_string : the cell command for the cell
        circ_id             : the circuit id for the cell (optional)
        payload_bytes       : the bytes in the cell payload (optional)
        force_link_version  : overrides the context link version (optional)
        force_payload_len   : overrides len(payload_bytes) (optional)
    Returns the cell bytes.
    '''
    context = get_connect_context(context)
    cell_bytes = bytearray()
    link_version = get_link_version(context, force_link_version)
    cell_link_version = cell.get('force_link_version', link_version)
    #print force_link_version, link_version, cell_link_version, cell.get('circ_id')
    return pack_cell(cell['cell_command_string'],
                     circ_id=cell.get('circ_id'),
                     payload_bytes=cell.get('payload_bytes'),
                     link_version=cell_link_version,
                     force_payload_len=cell.get('force_payload_len'))

def link_write_cell_list(context,
                         cell_list,
                         force_link_version=None):
    '''
    Pack and send the Tor cells specified by cell_list to the ssl_socket in
    context, using the link_version in context. force_link_version overrides
    the link_version in context.
    An empty cell list is allowed: no cells are sent.
    Each dict in cell_list is as in link_pack_cell().
    Returns the cell bytes sent on the wire.
    '''
    context = get_connect_context(context)
    cell_bytes = bytearray()
    link_version = get_link_version(context, force_link_version)
    for cell in cell_list:
        cell_bytes += link_pack_cell(context, cell)

    ssl_write(context, cell_bytes)
    return cell_bytes

def link_read_cell_bytes(context):
    '''
    Reads and returns bytes from the ssl_socket in context.
    Returns the cell bytes received.
    '''
    context = get_connect_context(context)
    return ssl_read(context)

def link_close(context,
               do_shutdown=True):
    '''
    Closes the Tor link in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    # There is no Tor cell command for closing a link
    context = get_connect_context(context)
    ssl_close(context, do_shutdown)

def link_request_cell_list(ip, port,
                           cell_list,
                           link_version_list=[3,4,5],
                           send_netinfo=True):
    '''
    Send the Tor cells in cell_list to ip and port, using link_version_list,
    Returns a tuple containing the context, and the response bytes.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = link_open(ip, port,
                        link_version_list=link_version_list,
                        send_netinfo=send_netinfo)
    link_write_cell_list(context, cell_list)
    response_cell_bytes = bytearray()
    if len(cell_list) > 0:
        response_cell_bytes = link_read_cell_bytes(context)
    link_close(context, True)
    return (context, response_cell_bytes)
