"""Load one private native ClamAV snapshot and check its typed reference graph.

Native fields, source identities and logical graph IDs stay distinct. Diagnostic
IDs are validation oracles, never source fields credited as removable storage.
SPDX-License-Identifier: GPL-2.0-only
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import struct

import numpy as np

NIL = (1 << 32) - 1
OBJ_EXTENSION = 4
CHUNK = 65536


def _bytes(path):
    path = Path(path)
    if not path.exists():
        raise ValueError('capture file is missing: ' + path.name)
    return np.memmap(path, dtype=np.uint8, mode='r') if path.stat().st_size else np.empty(0, np.uint8)


def _array(path, dtype, columns=1):
    data = _bytes(path)
    dtype = np.dtype(dtype)
    if len(data) % (dtype.itemsize * columns):
        raise ValueError('capture file has incomplete rows: ' + Path(path).name)
    return data.view(dtype).reshape(-1, columns) if columns != 1 else data.view(dtype)


def interval_union_bytes(starts, lengths):
    """Union readable address spans; never sum overlapping prefix/token spans."""
    starts = np.asarray(starts, dtype=np.uint64)
    lengths = np.asarray(lengths, dtype=np.uint64)
    if starts.shape != lengths.shape or starts.ndim != 1:
        raise ValueError('invalid span vectors')
    if np.any(lengths > np.uint64((1 << 64) - 1) - starts):
        raise ValueError('address span wraps')
    keep = lengths != 0
    starts, lengths = starts[keep], lengths[keep]
    if not len(starts):
        return 0
    order = np.argsort(starts, kind='stable')
    starts = starts[order]
    ends = starts + lengths[order]
    high = np.maximum.accumulate(ends)
    prior = np.empty_like(high)
    prior[0] = 0
    prior[1:] = high[:-1]
    lower = np.maximum(starts, prior)
    positive = ends > lower
    return int((ends[positive] - lower[positive]).sum(dtype=np.uint64))


def resolve_pointers(pointers, addresses):
    """Resolve private source words to original row IDs, preserving nulls."""
    pointers = np.asarray(pointers, dtype=np.uint64)
    addresses = np.asarray(addresses, dtype=np.uint64)
    if addresses.ndim != 1 or np.any(addresses == 0):
        raise ValueError('native record address oracle contains null')
    order = np.argsort(addresses, kind='stable')
    ordered = addresses[order]
    if len(ordered) > 1 and np.any(ordered[1:] == ordered[:-1]):
        raise ValueError('native record addresses are not unique')
    result = np.full(pointers.shape, NIL, dtype=np.uint32)
    valid = pointers != 0
    wanted = pointers[valid]
    positions = np.searchsorted(ordered, wanted)
    if np.any(positions >= len(ordered)):
        raise ValueError('source pointer is outside its captured type')
    if len(wanted) and np.any(ordered[positions] != wanted):
        raise ValueError('source pointer is absent from its captured type')
    result[valid] = order[positions].astype(np.uint32)
    return result


@dataclass
class Family:
    name: str
    columns: dict
    source_bits: dict
    native_bytes: int
    record_size: int
    rows: int
    addresses: np.ndarray | None = None
    _raw: np.ndarray | None = field(default=None, repr=False)
    _members: dict = field(default_factory=dict, repr=False)

    @property
    def named_bytes_per_record(self):
        return sum(width for _, width in self._members.values())

    def verify(self, result):
        """Replay every named native byte, independently of vector synthesis.

        Padding is measured in native_bytes but has no GET query. It is not
        compared as an observable field or claimed as an independently live
        allocation. Source pointer words are compared exactly, not merely names.
        """
        reconstructed = {}
        scalar_reads = 0
        scalar_rows = sorted(set([0, self.rows - 1] +
                                 np.linspace(0, max(0, self.rows - 1), min(self.rows, 31), dtype=int).tolist())) if self.rows else []
        for name, original in self.columns.items():
            values = np.asarray(result.reconstruct(name), dtype=np.uint64)
            if values.shape != original.shape or not np.array_equal(values, original):
                raise AssertionError('complete native field reconstruction differs: ' + self.name + '.' + name)
            for row in scalar_rows:
                if result.get(name, int(row)) != int(original[row]):
                    raise AssertionError('scalar GET differs from native record')
                scalar_reads += 1
            reconstructed[name] = values
        compared = 0
        if self._raw is not None:
            for start in range(0, self.rows, CHUNK):
                count = min(CHUNK, self.rows - start)
                source = self._raw[start * self.record_size:(start + count) * self.record_size].reshape(count, self.record_size)
                replay = np.zeros_like(source)
                mask = np.zeros(self.record_size, dtype=bool)
                for name, (offset, width) in self._members.items():
                    dtype = np.dtype('<u' + str(width))
                    values = reconstructed[name][start:start + count].astype(dtype)
                    replay[:, offset:offset + width] = values.view(np.uint8).reshape(count, width)
                    mask[offset:offset + width] = True
                if not np.array_equal(replay[:, mask], source[:, mask]):
                    raise AssertionError('native byte replay differs')
                compared += int(mask.sum()) * count
        return {'all_named_fields_equal': True, 'native_named_bytes_compared': compared,
                'scalar_gets_checked': scalar_reads, 'rows': self.rows,
                'source_pointer_words_preserved': True,
                'native_padding_bytes_outside_get_contract': self.native_bytes - self.rows * self.named_bytes_per_record}


@dataclass
class Capture:
    families: list
    manifest: dict
    graph_validation: dict
    retained_known_payload_bytes: int
    unknown_object_count: int
    layout: dict = field(repr=False)
    schema: dict = field(repr=False)


def _family(directory, name, filename, record_size, definitions, addresses=None):
    raw = _bytes(directory / filename)
    if record_size < 1 or len(raw) % record_size:
        raise ValueError('invalid native record file: ' + filename)
    rows = len(raw) // record_size
    columns, bits, members = {}, {}, {}
    occupied = np.zeros(record_size, dtype=bool)
    for label, description in definitions.items():
        width = int(description['element_bytes'])
        count = int(description['count'])
        offset = int(description['native_offset'])
        if width not in (1, 2, 4, 8) or count < 1 or offset < 0 or offset + count * width > record_size:
            raise ValueError('invalid native field definition')
        for index in range(count):
            at = offset + width * index
            key = label if count == 1 else f'{label}[{index}]'
            if key in columns or np.any(occupied[at:at + width]):
                raise ValueError('overlapping native fields')
            occupied[at:at + width] = True
            columns[key] = (np.ndarray((rows,), dtype='<u' + str(width), buffer=raw,
                                      offset=at, strides=(record_size,))
                            if rows else np.empty(0, dtype='<u' + str(width)))
            bits[key], members[key] = width * 8, (at, width)
    if addresses is not None:
        if len(addresses) != rows:
            raise ValueError('native address count differs from record count')
        ordered = np.sort(addresses)
        if np.any(ordered == 0) or (len(ordered) > 1 and np.any(ordered[1:] == ordered[:-1])):
            raise ValueError('native record identities are null or duplicated')
    return Family(name, columns, bits, len(raw), record_size, rows, addresses, raw, members)


def _objects(path):
    raw = _bytes(path)
    if len(raw) < 4:
        raise ValueError('truncated object header')
    count = struct.unpack_from('<I', raw)[0]
    if count > (len(raw) - 4) // 24:
        raise ValueError('impossible object count')
    kinds = np.empty(count, np.uint32)
    extents = np.empty(count, np.uint32)
    sizes = np.empty(count, np.uint32)
    addresses = np.empty(count, np.uint64)
    at = 4
    for index in range(count):
        if at + 24 > len(raw):
            raise ValueError('truncated object entry')
        kind, extent, size, _, address = struct.unpack_from('<IIIIQ', raw, at)
        at += 24
        if size > extent or size > len(raw) - at or not address:
            raise ValueError('invalid readable object extent')
        kinds[index], extents[index], sizes[index], addresses[index] = kind, extent, size, address
        at += size
    if at != len(raw):
        raise ValueError('trailing object bytes')
    if count > 1 and np.any(addresses[1:] <= addresses[:-1]):
        raise ValueError('object identities must be in unique source-address order')
    return kinds, extents, sizes, addresses


def _check_equal(actual, expected, message):
    if actual.shape != expected.shape or not np.array_equal(actual, expected):
        raise ValueError(message)


def load_capture(path):
    directory = Path(path)
    schema = json.loads((directory / 'graph-schema.json').read_text())
    layout = json.loads((directory / 'native-layout.json').read_text())
    if schema.get('schema') != 1 or layout.get('schema') != 1 or schema.get('endianness') != 'little':
        raise ValueError('unsupported capture schema')
    if layout.get('native_pointer_bytes') != 8:
        raise ValueError('this capture loader requires 64-bit source pointers')
    kinds, extents, sizes, object_addresses = _objects(directory / 'objects.bin')
    extension_addresses = object_addresses[(kinds & OBJ_EXTENSION) != 0]
    specifications = [('patterns', 'native_patterns.bin', 'pattern', 'pattern_addresses.bin'),
                      ('candidates', 'native_links.bin', 'candidate', 'link_addresses.bin'),
                      ('nodes', 'native_nodes.bin', 'node', 'node_addresses.bin'),
                      ('logical', 'native_logical.bin', 'logical', 'logical_addresses.bin'),
                      ('extensions', 'native_extensions.bin', 'extension', None)]
    families = []
    for name, filename, prefix, address_file in specifications:
        definitions = dict(layout[prefix + '_fields'])
        if prefix == 'logical':
            tdb = definitions.pop('tdb')
            for member, description in layout['tdb_fields'].items():
                description = dict(description)
                description['native_offset'] += tdb['native_offset']
                definitions['tdb.' + member] = description
        addresses = _array(directory / address_file, '<u8') if address_file else extension_addresses
        families.append(_family(directory, name, filename, layout[prefix + '_size'], definitions, addresses))
    by_name = {family.name: family for family in families}
    for name, key in [('patterns', 'patterns'), ('candidates', 'candidate_records'),
                      ('nodes', 'nodes'), ('logical', 'logical_records')]:
        if by_name[name].rows != schema[key]:
            raise ValueError('schema count differs from native records: ' + name)
    if len(object_addresses) != schema['objects']:
        raise ValueError('schema object count differs')
    transitions = _array(directory / 'transitions.bin', '<u4', 257)
    transition_addresses = _array(directory / 'transition_addresses.bin', '<u8')
    if len(transitions) != schema['transition_rows'] or len(transition_addresses) != len(transitions):
        raise ValueError('transition row count differs')
    destinations = np.ascontiguousarray(transitions[:, 1:]).reshape(-1)
    transition_family = Family('transition_values', {'destination': destinations}, {'destination': 32},
                               destinations.nbytes, 4, len(destinations), None,
                               destinations.view(np.uint8), {'destination': (0, 4)})
    families.append(transition_family)
    pointer_checks = 0
    links = _array(directory / 'links.bin', '<u4', 3)
    for col, name, addresses in [(0, 'me', by_name['patterns'].addresses),
                                 (1, 'next', by_name['candidates'].addresses),
                                 (2, 'next_same', by_name['candidates'].addresses)]:
        actual = resolve_pointers(by_name['candidates'].columns[name], addresses)
        _check_equal(actual, links[:, col], 'candidate source-pointer graph differs')
        pointer_checks += len(actual)
    node_graph = _array(directory / 'node_graph.bin', '<u4', 5)
    for col, name, addresses in [(2, 'list', by_name['candidates'].addresses),
                                 (3, 'fail', by_name['nodes'].addresses),
                                 (4, 'trans', transition_addresses)]:
        actual = resolve_pointers(by_name['nodes'].columns[name], addresses)
        _check_equal(actual, node_graph[:, col], 'node source-pointer graph differs')
        pointer_checks += len(actual)
    pattern_objects = _array(directory / 'pattern_objects.bin', '<u4', 4)
    for col, name in enumerate(['pattern', 'prefix', 'ext', 'virname']):
        actual = resolve_pointers(by_name['patterns'].columns[name], object_addresses)
        _check_equal(actual, pattern_objects[:, col], 'pattern object identity differs')
        pointer_checks += len(actual)
    logical_objects = _array(directory / 'logical_objects.bin', '<u4', 34)
    logical = by_name['logical']
    logical_members = ['virname', 'u', 'tdb.val', 'tdb.range', 'tdb.str', 'tdb.macro_ptids',
                       'tdb.icongrp1', 'tdb.icongrp2', 'tdb.intermediates']
    for col, name in enumerate(logical_members):
        if name in logical.columns:
            actual = resolve_pointers(logical.columns[name], object_addresses)
            _check_equal(actual, logical_objects[:, col], 'logical object identity differs')
            pointer_checks += len(actual)
    coordinate_names = ['target', 'engine', 'nos', 'ep', 'filesize', 'container', 'handlertype']
    for index, label in enumerate(coordinate_names):
        name = 'tdb.' + label
        if name not in logical.columns:
            continue
        actual = resolve_pointers(logical.columns[name], object_addresses)
        _check_equal(actual, logical_objects[:, 13 + index * 3], 'logical coordinate pointer differs')
        base_ids, offsets = logical_objects[:, 14 + index * 3], logical_objects[:, 15 + index * 3]
        valid = base_ids != NIL
        if np.any(base_ids[valid] >= len(object_addresses)):
            raise ValueError('logical coordinate has unknown source array')
        expected = object_addresses[base_ids[valid]] + offsets[valid].astype(np.uint64)
        _check_equal(logical.columns[name][valid], expected, 'logical coordinate offset differs')
        pointer_checks += len(actual)
    targets = _array(directory / 'targets.bin', '<u4', 9)
    maxima = {int(row[0]): int(row[8]) for row in targets}
    if len(maxima) != len(targets):
        raise ValueError('duplicate target identity')
    for target in np.unique(transitions[:, 0]):
        if int(target) not in maxima:
            raise ValueError('transition has unknown target')
        if np.any(transitions[transitions[:, 0] == target, 1:] > maxima[int(target)]):
            raise ValueError('transition points outside its target node range')
    for base_col, count_col, family in [(1, 2, 'patterns'), (3, 4, 'candidates'),
                                        (5, 6, 'logical'), (7, 8, 'nodes')]:
        cursor = 0
        for target in targets:
            if int(target[base_col]) != cursor:
                raise ValueError('target family ranges are not contiguous')
            cursor += int(target[count_col])
        if cursor != by_name[family].rows:
            raise ValueError('target range does not cover native family')
    retained = (kinds & OBJ_EXTENSION) == 0
    known_bytes = interval_union_bytes(object_addresses[retained], extents[retained])
    unknown = int(np.count_nonzero(retained & (extents == 0)))
    graph_validation = {'all_native_pointer_edges_equal_exported_id_graph': True,
                        'source_pointer_edges_compared': pointer_checks,
                        'transition_destinations_checked': len(destinations),
                        'target_ranges_cover_all_records': True,
                        'record_and_object_identities_not_merged': True}
    manifest = {'schema': 1, 'native_sizes': schema['native_sizes'],
                'patterns': by_name['patterns'].rows, 'candidate_records': by_name['candidates'].rows,
                'nodes': by_name['nodes'].rows, 'logical_records': by_name['logical'].rows,
                'extensions': by_name['extensions'].rows, 'transition_rows': len(transitions),
                'transition_values': len(destinations), 'objects': len(object_addresses),
                'known_retained_readable_span_union_bytes': known_bytes,
                'objects_with_unknown_extent': unknown,
                'additional_engine_and_allocator_bytes_unknown': True,
                'native_family_bytes': {f.name: f.native_bytes for f in families},
                'native_targets': layout.get('targets', []),
                'raw_input_policy': 'private native words and signature data; only counts and hashes may be published'}
    return Capture(families, manifest, graph_validation, known_bytes, unknown, layout, schema)
