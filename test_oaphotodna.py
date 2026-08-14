import unittest

import oaphotodna


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


if __name__ == '__main__':
    unittest.main()
