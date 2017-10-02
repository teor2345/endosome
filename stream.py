# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Stream-level functions

from pack import *
from cell import *
from link import *
from circuit import *

def get_stream_context(context):
    '''
    Return the stream context in context.
    '''
    # If it doesn't have a circuit, it's not a stream context
    assert 'circuit' in context
    return context

def get_circuit_streams(context):
    '''
    Return all the streams on the circuit in context, which must be a
    circuit or stream context.
    If context does not have streams, return an empty dict.
    '''
    # This will assert on the wrong kind of context
    circuit_context = get_circuit_context(context)
    return circuit_context.get('streams', {})

def get_link_streams(context):
    '''
    Return all the streams on the link in context, which can be any kind of
    context.
    If context does not have streams, return an empty dict.
    '''
    link = get_link_context(context)
    return [stream for stream  in get_circuit_streams(circuit)
                   for circuit in get_circuits(link)]

def is_stream_id_used(context, stream_id):
    '''
    Returns True if stream_id is used in context, and False if it is not.
    Context must be a circuit or stream context, as stream IDs are only unique
    on each circuit.
    '''
    circuit_context = get_circuit_context(context)
    return stream_id in get_circuit_streams(circuit_context)

def get_unused_stream_id(context):
    '''
    Returns the first valid, unused stream_id in context.
    Context must be a circuit or stream context, as stream IDs are only unique
    on each circuit.
    '''
    circuit_context = get_circuit_context(context)
    stream_id = get_min_valid_stream_id()
    # a randomised selection algorithm would be faster but more complex
    while is_stream_id_used(stream_id):
        stream_id += 1
        assert stream_id < get_max_valid_stream_id()
    return stream_id

def add_stream_context(circuit_context, stream_context):
    '''
    Add stream_context to circuit_context.
    '''
    circuit_context = get_circuit_context(circuit_context)
    stream_context = get_stream_context(stream_context)
    # This creates a circular reference, which modern python GCs can handle
    stream_id = stream_context['stream_id']
    assert not is_stream_id_used(circuit_context, stream_id)
    stream_context['circuit'] = circuit_context
    circuit_context.setdefault('streams', {})
    circuit_context['streams'][stream_id] = stream_context
    assert is_stream_id_used(circuit_context, stream_id)

def remove_stream_context(circuit_context, stream_context):
    '''
    Remove stream_context from circuit_context.
    '''
    circuit_context = get_circuit_context(circuit_context)
    stream_context = get_stream_context(stream_context)
    # This breaks the circular dependency created by add_stream_context()
    stream_id = stream_context['stream_id']
    assert is_stream_id_used(circuit_context, stream_id)
    del circuit_context['streams'][stream_id]
    assert not is_stream_id_used(circuit_context, stream_id)

# TODO: open streams
