# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii

from connect import *
from cell import *

# Link-level functions

def get_link_version(context, force_link_version=None):
    '''
    Return force_link_version, if it is not None, or the link version from
    context. Supports link and circuit contexts.
    If both are None, or context does not have a link version, return None.
    '''
    if force_link_version is not None:
        return force_link_version
    # Use the link context from circuit contexts
    if 'link' in context:
        context = context['link']
    return context.get('link_version')

def get_link_version_list(context, force_link_version=None):
    '''
    Return [force_link_version], if it is not None, or the link version list
    from context. Supports link and circuit contexts.
    If both are None, or context does not have a link version, return an empty
    list.
    '''
    if force_link_version is not None:
        return [force_link_version]
    # Use the link context from circuit contexts
    if 'link' in context:
        context = context['link']
    return context.get('link_version_list', [])

def unpack_cells_link(context, data_bytes,
                      force_link_version=None):
    '''
    Call unpack_cells() with the appropriate values from the link context,
    and return its result.
    '''
    link_version = get_link_version(context,
                                    force_link_version=force_link_version)
    link_version_list = get_link_version_list(context,
                                    force_link_version=force_link_version)
    return unpack_cells(data_bytes,
                        link_version_list=link_version_list,
                        force_link_version=link_version)

def link_open(ip, port,
              link_version_list=[3,4,5], force_link_version=None,
              send_netinfo=True, sender_timestamp=None, sender_ip_list=None,
              max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Open a link-level Tor connection to ip and port, using the highest
    link version in link_version_list supported by both sides.
    force_link_version overrides the negotiated link_version.

    If send_netinfo is true, send a NETINFO cell after the link version
    is negotiated, using ip as the receiver IP address, sender_timestamp
    and sender_ip_list. NETINFO cells are required by Tor.
    See https://trac.torproject.org/projects/tor/ticket/22951

    max_response_len is the maximum response size that will be read from the
    connection while setting up the link.

    Returns a context dictionary required to continue the connection:
        'link_version'             : the Tor cell link version used on the link
        'link_version_list'        : the list sent in the link VERSIONS cell
        'open_sent_cell_bytes'     : the cell bytes sent to open the connection
        'open_received_cell_bytes' : the cell bytes received when opening the
                                     connection
        'ssl_socket'               : a SSL-wrapped TCP socket connected to ip
                                    and port
        'tcp_socket'               : a TCP socket connected to ip and port

    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = ssl_open(ip, port)
    versions_cell_bytes = pack_versions_cell(link_version_list)
    open_sent_cell_bytes = versions_cell_bytes
    ssl_write(context, versions_cell_bytes)
    open_received_cell_bytes = ssl_read(context, max_response_len)
    (link_version, _) = unpack_cells(open_received_cell_bytes,
                                     link_version_list=link_version_list,
                                     force_link_version=force_link_version)
    if force_link_version:
        link_version = force_link_version
    # Now we know the link version, send a netinfo cell
    if send_netinfo:
        netinfo_cell_bytes = pack_netinfo_cell(ip,
                                             sender_timestamp=sender_timestamp,
                                             sender_ip_list=sender_ip_list,
                                             link_version=link_version)
        open_sent_cell_bytes += netinfo_cell_bytes
        ssl_write(context, netinfo_cell_bytes)
        # We don't expect anything in response to our NETINFO
    context.update({
            'link_version'             : link_version,
            'link_version_list'        : link_version_list,
            'open_sent_cell_bytes'     : open_sent_cell_bytes,
            'open_received_cell_bytes' : open_received_cell_bytes,
            })
    return context

def link_write_cell_list(context,
                         cell_list,
                         force_link_version=None):
    '''
    Pack and send the Tor cells specified by cell_list to the ssl_socket in
    context, using the link_version in context. force_link_version overrides
    the link_version in context.
    An empty cell list is allowed: no cells are sent.
    Each dict in cell_list can have the following elements:
        cell_command_string, circ_id (optional), payload (optional),
        force_link_version (optional).
    Returns the cell bytes sent on the wire.
    '''
    cell_bytes = bytearray()
    link_version = get_link_version(context, force_link_version)
    for cell in cell_list:
        cell_link_version = cell.get('force_link_version', link_version)
        cell_bytes += pack_cell(cell['cell_command_string'],
                                circ_id=cell.get('circ_id'),
                                payload=cell.get('payload'),
                                link_version=cell_link_version)
    ssl_write(context, cell_bytes)
    return cell_bytes

def make_cell(cell_command_string, circ_id=None, payload=None,
                 force_link_version=None):
    '''
    Return a dictionary containing the cell contents, as in link_write_cell().
    '''
    cell = {}
    cell['cell_command_string'] = cell_command_string
    if circ_id is not None:
        cell['circ_id'] = circ_id
    if payload is not None:
        cell['payload'] = payload
    if force_link_version is not None:
        cell['force_link_version'] = force_link_version
    return cell

def link_write_cell(context,
                    cell_command_string, circ_id=None, payload=None,
                    force_link_version=None):
    '''
    Write a Tor cell with cell_command_string, circ_id, and payload.
    Returns the cell bytes sent on the wire.
    See link_write_cell_list() for details.    
    '''
    cell = make_cell(cell_command_string, circ_id=circ_id, payload=payload,
                     force_link_version=force_link_version)
    return link_write_cell_list(context,
                                [cell],
                                # This is redundant, but we do it anyway
                                force_link_version=force_link_version)
    
def link_read_cell_bytes(context,
                         force_link_version=None,
                         max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the ssl_socket in
    context, using the link_version in context.
    Returns the cell bytes received.
    force_link_version overrides the link_version in context.
    '''
    received_bytes = ssl_read(context, max_response_len)
    link_version = get_link_version(context, force_link_version)
    return received_bytes

def link_close(context,
               do_shutdown=True):
    '''
    Closes the Tor link in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    # There is no Tor cell command for closing a link
    ssl_close(context, do_shutdown)

def link_request_cell_list(ip, port,
                           cell_list,
                           link_version_list=[3,4,5], force_link_version=None,
                           send_netinfo=True, sender_timestamp=None,
                           sender_ip_list=None,
                           max_response_len=MAX_READ_BUFFER_LEN,
                           do_shutdown=True):
    '''
    Send the Tor cells in cell_list to ip and port, using link_version_list,
    (force_link_version overrides the negotiated link_version),
    and read at most max_response_len bytes of response cells.
    If do_shutdown is True, shut down the socket immediately after reading the
    response.
    Returns a tuple containing the context, and the response bytes.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = link_open(ip, port,
                        link_version_list=link_version_list,
                        force_link_version=force_link_version,
                        send_netinfo=send_netinfo,
                        sender_timestamp=sender_timestamp,
                        sender_ip_list=sender_ip_list,
                        max_response_len=max_response_len)
    link_write_cell_list(context,
                         cell_list,
                         force_link_version=force_link_version)
    response_cell_bytes = bytearray()
    if len(cell_list) > 0:
        response_cell_bytes = link_read_cell_bytes(context,
                                        force_link_version=force_link_version,
                                        max_response_len=max_response_len)
    link_close(context, do_shutdown)
    return (context, response_cell_bytes)

def link_request_cell(ip, port,
                      cell_command_string, circ_id=None, payload=None,
                      link_version_list=[3,4,5], force_link_version=None,
                      send_netinfo=True, sender_timestamp=None,
                      sender_ip_list=None,
                      max_response_len=MAX_READ_BUFFER_LEN,
                      do_shutdown=True):
    '''
    Send a Tor cell with cell_command_string, circ_id, and payload.
    See link_request_cell_list() for details.
    '''
    cell = make_cell(cell_command_string, circ_id=circ_id, payload=payload,
                     force_link_version=force_link_version)
    return link_request_cell_list(ip, port,
                                  [cell],
                                  link_version_list=link_version_list,
                                  force_link_version=force_link_version,
                                  send_netinfo=send_netinfo,
                                  sender_timestamp=sender_timestamp,
                                  sender_ip_list=sender_ip_list,
                                  max_response_len=max_response_len,
                                  do_shutdown=do_shutdown)

def format_cell_bytes(context, cell_bytes,
                      initial_cells=False,
                      force_link_version=None,
                      skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in cell_bytes using format_cells(), supplying
    the relevant arguments from context.
    If initial_cells is True, automatically determines the link version from
    the initial VERSIONS cell.
    Supports link and circuit contexts.
    Returns a string formatted according to the arguments.
    '''
    link_version = None
    if not initial_cells:
        link_version = get_link_version(context, force_link_version)
    link_version_list = get_link_version_list(context,
                                        force_link_version=force_link_version)
    return format_cells(cell_bytes,
                        # we must use force_link_version, because only the
                        # caller knows when we are parsing a VERSIONS cell
                        link_version_list=link_version_list,
                        force_link_version=link_version,
                        skip_cell_bytes=skip_cell_bytes,
                        skip_zero_padding=skip_zero_padding)

# compatibility with older scripts
link_format_cell_bytes = format_cell_bytes
