from pathlib import Path
import tempfile
import unittest

from tool import write_verified_member


class ToolCacheTests(unittest.TestCase):
    def test_retry_preserves_verified_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'tool.exe'
            write_verified_member(file, b'fixture-binary')
            previous = file.stat().st_mtime_ns
            write_verified_member(file, b'fixture-binary')
            self.assertEqual(file.stat().st_mtime_ns, previous)

    def test_same_size_corruption_is_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'tool.exe'
            file.write_bytes(b'corrupt')
            write_verified_member(file, b'checked')
            self.assertEqual(file.read_bytes(), b'checked')


if __name__ == '__main__':
    unittest.main()
