"""Optional Kvrocks Search storage and nearest-neighbour search for PhotoDNA hashes.

This module deliberately depends only on the client interface implemented by
``redis-py``.  Applications may pass an existing compatible client, so using
the local hash and distance functions never requires Kvrocks or redis-py.
"""

from array import array
import importlib
import sys


PHOTODNA_HASH_DIMENSIONS = 144


def hash_to_float32(hash_value, dimensions=PHOTODNA_HASH_DIMENSIONS):
    """Encode a PhotoDNA byte vector as the FLOAT32 blob Kvrocks expects."""
    if len(hash_value) != dimensions:
        raise ValueError(f'Hash must contain exactly {dimensions} values')
    if any(not isinstance(value, int) or not 0 <= value <= 255
           for value in hash_value):
        raise ValueError('Hash values must be integers between 0 and 255')

    values = array('f', hash_value)
    if sys.byteorder != 'little':
        values.byteswap()
    return values.tobytes()


def connect_kvrocks(url='redis://localhost:6666/0', **kwargs):
    """Create a redis-py client, keeping redis-py an optional dependency."""
    redis = importlib.import_module('redis')
    return redis.Redis.from_url(url, **kwargs)


class KvrocksPhotoDNAIndex:
    """A small wrapper around Kvrocks Search's vector commands.

    L2 is used so the returned score has the same meaning as the Euclidean
    distance returned by :func:`oaphotodna.compare_hashes`.
    """

    def __init__(self, client, index_name='photodna', key_prefix='photodna:',
                 dimensions=PHOTODNA_HASH_DIMENSIONS):
        if not index_name or not key_prefix:
            raise ValueError('Index name and key prefix must not be empty')
        if dimensions <= 0:
            raise ValueError('Dimensions must be positive')
        self.client = client
        self.index_name = index_name
        self.key_prefix = key_prefix
        self.dimensions = dimensions

    def create_index(self, algorithm='HNSW'):
        """Create the HASH index. Call once when provisioning Kvrocks."""
        algorithm = algorithm.upper()
        if algorithm not in ('HNSW', 'FLAT'):
            raise ValueError('Algorithm must be HNSW or FLAT')
        return self.client.execute_command(
            'FT.CREATE', self.index_name,
            'ON', 'HASH',
            'PREFIX', 1, self.key_prefix,
            'SCHEMA',
            'identifier', 'TAG',
            'vector', 'VECTOR', algorithm, 6,
            'TYPE', 'FLOAT32',
            'DIM', self.dimensions,
            'DISTANCE_METRIC', 'L2',
        )

    def add(self, identifier, hash_value, **metadata):
        """Add or replace one hash and optional scalar metadata."""
        if not identifier:
            raise ValueError('Identifier must not be empty')
        vector = hash_to_float32(hash_value, self.dimensions)
        mapping = {'identifier': str(identifier), 'vector': vector}
        mapping.update({str(key): str(value) for key, value in metadata.items()})
        return self.client.hset(f'{self.key_prefix}{identifier}', mapping=mapping)

    def search(self, hash_value, limit=10):
        """Return nearest hashes as dictionaries containing key and distance."""
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError('Limit must be a positive integer')
        response = self.client.execute_command(
            'FT.SEARCH', self.index_name,
            f'*=>[KNN {limit} @vector $query_vector AS distance]',
            'PARAMS', 2, 'query_vector',
            hash_to_float32(hash_value, self.dimensions),
            'SORTBY', 'distance',
            'RETURN', 2, 'identifier', 'distance',
            'LIMIT', 0, limit,
            'DIALECT', 2,
        )
        return self._parse_search_response(response)

    @staticmethod
    def _text(value):
        return value.decode() if isinstance(value, bytes) else str(value)

    @classmethod
    def _parse_search_response(cls, response):
        # Kvrocks uses the RediSearch RESP2 shape: total, key, fields, ...
        results = []
        for offset in range(1, len(response), 2):
            key = cls._text(response[offset])
            fields = response[offset + 1]
            item = {'key': key}
            for field_offset in range(0, len(fields), 2):
                name = cls._text(fields[field_offset])
                value = cls._text(fields[field_offset + 1])
                item[name] = float(value) if name == 'distance' else value
            results.append(item)
        return results
