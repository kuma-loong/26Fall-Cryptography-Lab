"""实验结果核对：python -m unittest -v test_lab1.py（解密仅在验证侧）。"""

import ast
import itertools
from pathlib import Path
import unittest

from ecb_common import (
    DEMO_KEY, HISTORY_MESSAGES, ecb_decrypt, ecb_encrypt,
    format_aligned, parse_aligned,
)
from task4_forge import FIELD_KEY, forge, forge_many, search_sources


class Lab1Tests(unittest.TestCase):
    def setUp(self):
        self.history = [
            dict(id=mid, sender=sender, to=to, date=date, place=place,
                 ciphertext_hex=ecb_encrypt(
                     DEMO_KEY, format_aligned(sender, to, date, place).encode()
                 ).hex())
            for mid, sender, to, date, place in HISTORY_MESSAGES
        ]

    def test_all_1296_field_combinations(self):
        for selected in itertools.product(self.history, repeat=4):
            sources = {field: msg['id'] for field, msg in zip(FIELD_KEY, selected)}
            ciphertext, _ = forge_many(self.history, 'M1', sources)
            expected = {FIELD_KEY[field]: msg[FIELD_KEY[field]]
                        for field, msg in zip(FIELD_KEY, selected)}
            self.assertEqual(parse_aligned(ecb_decrypt(DEMO_KEY, ciphertext)), expected)

    def test_single_field(self):
        ciphertext, _ = forge(self.history, 'M1', 'Place', 'M2')
        self.assertEqual(parse_aligned(ecb_decrypt(DEMO_KEY, ciphertext)),
                         dict(sender='Alice', to='Bob', date='2026-03-15', place='Gym'))

    def test_auto_search(self):
        wanted = dict(From='Bob', To='Carol', Date='2026-03-22', Place='Gym')
        self.assertEqual(search_sources(self.history, wanted),
                         dict(From='M5', To='M6', Date='M3', Place='M2'))

    def test_attacker_imports(self):
        tree = ast.parse(Path(__file__).with_name('task4_forge.py').read_text())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'__future__', 'block_utils', 'pathlib'})
        direct = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                  for alias in node.names}
        self.assertEqual(direct, {'argparse', 'json'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
