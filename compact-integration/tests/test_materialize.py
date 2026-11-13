"""Fail closed on patch/source drift without building a native engine."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('compact_build', Path(__file__).resolve().parents[1] / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class MaterializeTests(unittest.TestCase):
    def test_checked_paths(self):
        for name in ('/absolute', '../outside', 'a/../../outside', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build.checked_relative(name)

    def test_blob_preimages_and_postimages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'source.c'
            path.write_text('before\n')
            before = subprocess.check_output(['git', 'hash-object', str(path)], text=True).strip()
            path.write_text('after\n')
            after = subprocess.check_output(['git', 'hash-object', str(path)], text=True).strip()
            patch = root / 'change.patch'
            patch.write_text(f'diff --git a/source.c b/source.c\nindex {before}..{after} 100644\n')
            build.patch_images(root, patch, after=True)
            with self.assertRaises(ValueError):
                build.patch_preimages(root, patch)
            path.write_text('before\n')
            build.patch_preimages(root, patch)
            with self.assertRaises(ValueError):
                build.patch_images(root, patch, after=True)
            path.write_text('different\n')
            with self.assertRaises(ValueError):
                build.patch_preimages(root, patch)

    def test_missing_blob_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch = root / 'change.patch'
            patch.write_text('diff --git a/source.c b/source.c\n--- a/source.c\n+++ b/source.c\n')
            with self.assertRaises(ValueError):
                build.patch_preimages(root, patch)


if __name__ == '__main__':
    unittest.main()
