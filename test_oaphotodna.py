import unittest

import oaphotodna
from kvrocks_photodna import KvrocksPhotoDNAIndex, hash_to_float32


class HashComparisonTests(unittest.TestCase):
    def test_identical_hashes_have_full_similarity(self):
        self.assertEqual(oaphotodna.similarity_score([0, 127, 255], [0, 127, 255]), 1.0)

    def test_euclidean_similarity_is_normalized(self):
        self.assertEqual(oaphotodna.similarity_score([0, 0], [255, 255]), 0.0)

    def test_manhattan_similarity_uses_manhattan_normalization(self):
        self.assertEqual(
            oaphotodna.similarity_score([0, 0], [255, 0], metric='manhattan'),
            0.5,
        )

    def test_empty_hashes_are_rejected_for_similarity(self):
        with self.assertRaisesRegex(ValueError, 'must not be empty'):
            oaphotodna.similarity_score([], [])

    def test_mismatched_hash_lengths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'same length'):
            oaphotodna.compare_hashes([0], [0, 1])


class FakeKvrocksClient:
    def __init__(self, search_response=None):
        self.commands = []
        self.hashes = {}
        self.search_response = search_response or [0]

    def execute_command(self, *args):
        self.commands.append(args)
        if args[0] == 'FT.SEARCH':
            return self.search_response
        return b'OK'

    def hset(self, key, mapping):
        self.hashes[key] = mapping
        return 1


class KvrocksPhotoDNAIndexTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeKvrocksClient()
        self.index = KvrocksPhotoDNAIndex(self.client)
        self.photo_hash = list(range(144))

    def test_float32_encoding_has_expected_size(self):
        self.assertEqual(len(hash_to_float32(self.photo_hash)), 144 * 4)

    def test_create_index_uses_l2_float32_vector(self):
        self.index.create_index()
        command = self.client.commands[0]
        self.assertEqual(command[0], 'FT.CREATE')
        self.assertIn('HNSW', command)
        self.assertIn('FLOAT32', command)
        self.assertIn('L2', command)

    def test_add_stores_vector_and_metadata(self):
        self.index.add('example', self.photo_hash, source='test')
        stored = self.client.hashes['photodna:example']
        self.assertEqual(stored['identifier'], 'example')
        self.assertEqual(stored['source'], 'test')
        self.assertEqual(len(stored['vector']), 576)

    def test_search_uses_knn_and_parses_distances(self):
        self.client.search_response = [
            1, b'photodna:example',
            [b'identifier', b'example', b'distance', b'12.5'],
        ]
        results = self.index.search(self.photo_hash, limit=3)
        self.assertEqual(results, [{
            'key': 'photodna:example',
            'identifier': 'example',
            'distance': 12.5,
        }])
        command = self.client.commands[0]
        self.assertIn('*=>[KNN 3 @vector $query_vector AS distance]', command)

    def test_invalid_hash_is_rejected_before_storage(self):
        with self.assertRaisesRegex(ValueError, 'exactly 144'):
            self.index.add('short', [1, 2, 3])


if __name__ == '__main__':
    unittest.main()
