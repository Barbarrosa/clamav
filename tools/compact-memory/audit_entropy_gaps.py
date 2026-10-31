#!/usr/bin/env python3
"""Audit a corrected exact-layout export. Not an engine codec or universal bound.

Reports conditional counting bounds, H0 benchmarks, and independently decodable
constant/raw/sparse/run layouts. All dictionary IDs and simple layouts are
round-tripped. Exporter-generated identity columns are marked, not charged as
native fields. Requirements: Python 3, numpy.
"""
import argparse
from collections import Counter
import hashlib
import heapq
import json
import math
from pathlib import Path
import struct

import numpy as np

NAMES = ['export_id', 'name_id', 'extension_id', 'sigid', 'lsigid0',
         'lsigid1', 'lsigid2', 'offdata0', 'offdata1', 'offdata2', 'offdata3',
         'offset_min', 'offset_max', 'length0', 'length1', 'length2',
         'prefix_length0', 'prefix_length1', 'prefix_length2', 'parts',
         'partno', 'rtype', 'type', 'depth', 'sigopts']
WIDTHS = [4]*13 + [2]*10 + [1]*2


def entropy(counts):
    n = sum(int(x) for x in counts)
    return sum(int(c)*math.log2(n/int(c)) for c in counts if c)


def counting(counts):
    """log2(n! / product(c!)), conditioned on labeled symbol frequencies."""
    n = sum(int(x) for x in counts)
    return max(0.0, (math.lgamma(n+1)-sum(math.lgamma(int(c)+1) for c in counts))/math.log(2))


def column(v, width):
    v = np.asarray(v)
    n = len(v)
    values, counts = np.unique(v, return_counts=True)
    default = int(values[counts.argmax()])
    pos = np.flatnonzero(v != default).astype('<u4')
    starts = np.r_[0, np.flatnonzero(v[1:] != v[:-1])+1].astype('<u4')
    # Header: 64-bit length, 32-bit default, 32-bit count, 8-bit mode/width.
    header = 18
    sizes = {'raw': header+n*width,
             'sparse': header+len(pos)*(4+width),
             'runs': header+len(starts)*(4+width)}
    if len(values) == 1:
        sizes['constant'] = header
    chosen = 'constant' if len(values) == 1 else min(sizes, key=sizes.get)
    if chosen in ('constant', 'sparse'):
        payload = pos.tobytes()+v[pos].astype(f'<u{width}').tobytes()
        count = len(pos)
        restored = np.full(n, default, dtype=v.dtype)
        p = np.frombuffer(payload[:4*count], dtype='<u4')
        vals = np.frombuffer(payload[4*count:], dtype=f'<u{width}')
        restored[p] = vals
    elif chosen == 'runs':
        payload = starts.tobytes()+v[starts].astype(f'<u{width}').tobytes()
        count = len(starts)
        p = np.frombuffer(payload[:4*count], dtype='<u4')
        vals = np.frombuffer(payload[4*count:], dtype=f'<u{width}')
        restored = np.repeat(vals, np.diff(np.r_[p.astype(np.int64), n]))
    else:
        payload = v.astype(f'<u{width}').tobytes()
        restored = np.frombuffer(payload, dtype=f'<u{width}')
    assert np.array_equal(v, restored)
    assert sizes[chosen] == header+len(payload)
    return {'n':n, 'width':width, 'distinct':len(values), 'default':default,
            'exceptions':len(pos), 'runs':len(starts), 'raw_bytes':n*width,
            'h0_bits':entropy(counts), 'fixed_histogram_counting_bits':counting(counts),
            'symbol_and_frequency_table_bytes':len(values)*(width+4),
            'simple_layout_bytes':sizes[chosen], 'simple_layout_mode':chosen,
            'raw_to_simple_ratio':n*width/sizes[chosen],
            'all_values_verified':True,
            'top_values':[[int(values[i]),int(counts[i])] for i in np.argsort(counts)[-5:][::-1]]}


def block_columns(a):
    """Exact byte accounting of the existing scalar codec (1024 rows/block)."""
    totals = {k:0 for k in a.dtype.names}
    for name in a.dtype.names:
        for start in range(0,len(a),1024):
            v = a[name][start:start+1024].astype(np.uint64)
            n = len(v)
            lo, hi = int(v.min()), int(v.max())
            amount = (n*(hi-lo).bit_length()+7)//8
            if lo == hi or np.array_equal(v, np.arange(n,dtype=np.uint64)+v[0]):
                amount = 0
            else:
                _, c = np.unique(v, return_counts=True)
                sparse = ((n+63)//64)*10+(n-int(c.max()))*4
                amount = min(amount,sparse)
            totals[name] += 12+amount
    return totals


def entries(path):
    data = path.read_bytes()
    p = 0
    while p < len(data):
        if p+4 > len(data):
            raise ValueError('Truncated length')
        size, = struct.unpack_from('<I',data,p)
        p += 4
        if size > len(data)-p:
            raise ValueError('Truncated value')
        yield data[p:p+size]
        p += size


def dictionary(path):
    table, values, ids = {}, [], []
    original = list(entries(path))
    for value in original:
        if value not in table:
            table[value] = len(values)
            values.append(value)
        ids.append(table[value])
    assert all(values[i] == v for i,v in zip(ids,original))
    a = np.asarray(ids,dtype='<u4')
    stats = column(a,4)
    payload = sum(map(len,values))
    offsets = 4*(len(values)+1)
    freq = 4*len(values)
    # Empty entry is only an escape MARKER. Original escape objects must remain.
    return a, {'original_exported_payload_bytes':sum(map(len,original)),
               'distinct_including_escape_marker':len(values),
               'escape_records':sum(not x for x in original),
               'dictionary_payload_bytes':payload, 'dictionary_offset_bytes':offsets,
               'frequency_bytes':freq, 'ids':stats,
               'dictionary_plus_h0_and_frequencies_bytes':payload+offsets+freq+stats['h0_bits']/8,
               'dictionary_plus_simple_ids_bytes':payload+offsets+stats['simple_layout_bytes'],
               'all_entries_verified':True}


def huffman_witness(ids, group=64):
    """Serialized indexed prefix code: charge dictionary, checkpoints and tree.

    This is a space witness with <= group * maximum_code_bits bit steps/access,
    not a performance-qualified decoder. Python construction objects are excluded
    from the serialized layout, just as compiler scratch is excluded elsewhere.
    """
    frequencies = Counter(map(int,ids))
    heap = [(count,i,i) for i,count in sorted(frequencies.items())]
    heapq.heapify(heap)
    serial = max(frequencies)+1
    while len(heap)>1:
        a = heapq.heappop(heap); b = heapq.heappop(heap)
        heapq.heappush(heap,(a[0]+b[0],serial,(a[2],b[2])))
        serial += 1
    tree = heap[0][2]
    codes = {}
    def walk(node,code,length):
        if isinstance(node,int):
            codes[node] = (code,max(1,length))
        else:
            walk(node[0],code*2,length+1)
            walk(node[1],code*2+1,length+1)
    walk(tree,0,0)
    # Compact decoder node: 3 uint32 values (left, right, symbol).
    nodes = []
    def save(node):
        index = len(nodes); nodes.append(None)
        if isinstance(node,int):
            nodes[index] = (0xffffffff,0xffffffff,node)
        else:
            left,right = save(node[0]),save(node[1])
            nodes[index] = (left,right,0xffffffff)
        return index
    save(tree)
    treebytes = b''.join(struct.pack('<III',*node) for node in nodes)
    payload = bytearray(); offsets = []; acc = bits = 0
    for start in range(0,len(ids),group):
        offsets.append(len(payload))
        for symbol in ids[start:start+group]:
            code,length = codes[int(symbol)]
            acc = (acc << length)|code; bits += length
            while bits >= 8:
                bits -= 8; payload.append((acc >> bits)&255)
        if bits:
            payload.append((acc << (8-bits))&255)
        acc = bits = 0
    offsets.append(len(payload))
    indexbytes = struct.pack('<'+'I'*len(offsets),*offsets)
    saved_offsets = np.frombuffer(indexbytes,dtype='<u4')
    saved_tree = np.frombuffer(treebytes,dtype='<u4').reshape(-1,3)
    restored = []
    for b,start in enumerate(range(0,len(ids),group)):
        bit = int(saved_offsets[b])*8
        for _ in range(min(group,len(ids)-start)):
            node = 0
            while saved_tree[node,2] == 0xffffffff:
                direction = (payload[bit//8] >> (7-bit%8))&1
                bit += 1
                node = int(saved_tree[node,direction])
            restored.append(int(saved_tree[node,2]))
        assert bit <= int(saved_offsets[b+1])*8
    assert np.array_equal(ids,np.asarray(restored,dtype='<u4'))
    header = 24
    return {'group':group,'payload_bytes':len(payload),'index_bytes':len(indexbytes),
            'decoder_tree_bytes':len(treebytes),'header_bytes':header,
            'total_bytes':len(payload)+len(indexbytes)+len(treebytes)+header,
            'maximum_code_bits':max(length for _,length in codes.values()),
            'every_block_independently_decoded_and_all_ids_verified':True,
            'format_sha256':hashlib.sha256(payload+indexbytes+treebytes).hexdigest()}


def conditional(x,y):
    joint = Counter(zip(map(int,x),map(int,y)))
    return max(0.0, entropy(joint.values())-entropy(Counter(map(int,x)).values()))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path)
    p.add_argument('output',type=Path)
    args = p.parse_args()
    d = args.directory
    dtype = np.dtype(list(zip(NAMES,[f'<u{w}' for w in WIDTHS])))
    assert dtype.itemsize == 74
    a = np.fromfile(d/'patterns.bin',dtype=dtype)
    old = block_columns(a)
    fields = []
    for k,w in zip(NAMES,WIDTHS):
        s = column(a[k],w)
        s.update(name=k, existing_block1024_bytes=old[k],
                 is_exporter_generated=k=='export_id',
                 native_width=8 if k in ('name_id','extension_id') else (0 if k=='export_id' else w))
        fields.append(s)
    comparisons = []
    for i,x in enumerate(NAMES[3:]):
        for y in NAMES[3+i+1:]:
            eq = int(np.count_nonzero(a[x] == a[y]))
            if eq >= len(a)*0.99:
                comparisons.append({'a':x,'b':y,'equal':eq,'different':len(a)-eq})
    t,ts = dictionary(d/'templates.bin')
    e,es = dictionary(d/'programs.bin')
    ts['indexed_huffman_ids'] = huffman_witness(t)
    es['indexed_huffman_ids'] = huffman_witness(e)
    dependencies = []
    for base,dependent in [('length0','length1'),('length0','length2'),
                           ('prefix_length0','prefix_length1'),('prefix_length0','prefix_length2'),
                           ('offset_min','offset_max')]:
        positions = np.flatnonzero(a[base]!=a[dependent]).astype('<u4')
        width = a[dependent].dtype.itemsize
        raw = positions.tobytes()+a[dependent][positions].tobytes()
        restored = a[base].copy()
        count = len(positions)
        pos = np.frombuffer(raw[:count*4],dtype='<u4')
        vals = np.frombuffer(raw[count*4:],dtype=f'<u{width}')
        restored[pos] = vals
        assert np.array_equal(restored,a[dependent])
        dependencies.append({'base':base,'dependent':dependent,'exceptions':count,
                             'native_field_bytes':len(a)*width,
                             'exception_layout_bytes':22+len(raw),
                             'existing_block1024_bytes':old[dependent],
                             'exceptions_without_extension':int(np.count_nonzero(a['extension_id'][positions]==0xffffffff)),
                             'all_values_verified':True})
    logical = np.fromfile(d/'logical.bin',dtype='<u4').reshape(-1,7)
    assert len(t)==len(e)==len(logical)
    links = np.fromfile(d/'links.bin',dtype='<u4').reshape(-1,3)
    nodes = np.fromfile(d/'nodes.bin',dtype='<u4').reshape(-1,2)
    result = {'method':'Conditional counting bounds are family bounds, H0 is a model benchmark, simple layouts are constructive upper bounds; none is an unconditional per-instance lower bound.',
              'source_sha256':{f:hashlib.sha256((d/f).read_bytes()).hexdigest() for f in ['patterns.bin','templates.bin','programs.bin','logical.bin','links.bin','nodes.bin']},
              'patterns':fields, 'near_equal_pattern_fields':comparisons,
              'conditional_copy_fields':dependencies,
              'templates':ts,'expressions':es,
              'logical_columns':{k:column(logical[:,i],4) for i,k in enumerate(['id','bc_idx','type','flag','name_id','export_program_id','export_template_id'])},
              'conditional':{'template_given_expression_h0_bits':conditional(e,t),
                             'expression_given_template_h0_bits':conditional(t,e)},
              'links':{k:column(links[:,i],4) for i,k in enumerate(['pattern_id','next','next_same'])},
              'nodes':{k:column(nodes[:,i],4) for i,k in enumerate(['list','fail'])}}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(args.output),'pattern_fields_over_100x_simple':[s['name'] for s in fields if s['raw_to_simple_ratio']>=100 and not s['is_exporter_generated']], 'templates':ts,'expressions':es,'conditional':result['conditional']},indent=2))


if __name__=='__main__':
    main()
