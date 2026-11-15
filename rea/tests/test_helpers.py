import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def helper(name):
    return runpy.run_path(str(ROOT / "scripts" / name))


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()

    def command(self, script, *arguments):
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / script), *map(str, arguments)], capture_output=True, text=True)

    def manifest(self, **overrides):
        data = b"abcdef"
        source = self.work / "original"
        source.write_bytes(data)
        source.chmod(0o755)
        value = {"target": "original", "target_sha256": hashlib.sha256(data).hexdigest(), "patches": [
            {"id": "fixture", "reason": "local synthetic test", "offset": 1, "match": "62 63", "replace": "42 43"}]}
        value.update(overrides)
        manifest = self.work / "manifest.json"
        manifest.write_text(json.dumps(value))
        return source, manifest, value

    def test_patch_round_trip_preserves_original_and_executable_bit(self):
        source, manifest, value = self.manifest()
        output = self.work / "patched"
        result = self.command("apply-patch.py", manifest, source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), b"abcdef")
        self.assertEqual(output.read_bytes(), b"aBCdef")
        if os.name != "nt":
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
        self.assertNotEqual(self.command("apply-patch.py", manifest, source, output).returncode, 0)
        self.assertNotEqual(self.command("apply-patch.py", manifest, source, source).returncode, 0)

    def test_patch_rejects_hash_mismatch_and_changed_preimage(self):
        source, manifest, value = self.manifest()
        output = self.work / "patched"
        source.write_bytes(b"changed")
        self.assertNotEqual(self.command("apply-patch.py", manifest, source, output).returncode, 0)
        self.assertNotEqual(self.command("apply-patch.py", manifest, source, output, "--force").returncode, 0)
        self.assertFalse(output.exists())

    def test_manifest_validation_rejects_missing_hash_empty_overlap_and_negative_offsets(self):
        source, manifest, value = self.manifest()
        load = helper("apply-patch.py")["load_manifest"]
        cases = [{**value, "target_sha256": ""}, {**value, "patches": []},
                 {**value, "patches": [{**value["patches"][0], "offset": -1}]},
                 {**value, "patches": [value["patches"][0], {**value["patches"][0], "id": "second"}]},
                 {**value, "patches": [{**value["patches"][0], "match": "", "replace": ""}]}]
        for invalid in cases:
            with self.subTest(invalid=invalid):
                manifest.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    load(manifest)

    def test_x86_scanner_handles_near_branch_and_end_of_buffer(self):
        scan = helper("find-patch-sites.py")["find_x86"]
        self.assertEqual(scan(bytes.fromhex("0f8504000000"), "jcc")[0]["target"], 10)
        self.assertEqual(scan(bytes.fromhex("7412"), "jcc")[0]["invert"], "jne")
        self.assertEqual(scan(bytes.fromhex("e800000000"), "call")[0]["target"], 5)
        self.assertEqual(scan(bytes.fromhex("0f85"), "any"), [])

    def test_arm64_scanner_includes_last_instruction_and_rejects_reserved_encoding(self):
        scan = helper("find-patch-sites.py")["find_arm64"]
        result = scan(bytes.fromhex("40000054"), "jcc")
        self.assertEqual(result[0]["label"], "b.eq")
        self.assertEqual(result[0]["target"], 8)
        self.assertEqual(scan(bytes.fromhex("50000054"), "jcc"), [])

    def test_architecture_detection_uses_macho_cpu_not_word_size(self):
        detect = helper("find-patch-sites.py")["detect_arch"]
        for cpu, expected in [(0x01000007, "x86"), (0x0100000C, "arm64")]:
            self.assertEqual(detect(struct.pack("<II", 0xFEEDFACF, cpu)), expected)
        arm32 = bytearray(32)
        arm32[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", arm32, 18, 0x28)
        with self.assertRaises(ValueError):
            detect(arm32)

    def test_pe_mapping_separates_va_rva_headers_and_bss(self):
        data = bytearray(0x400)
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xE0)
        struct.pack_into("<H", data, 0x98, 0x10B)
        struct.pack_into("<I", data, 0x98 + 28, 0x400000)
        struct.pack_into("<I", data, 0x98 + 60, 0x200)
        struct.pack_into("<IIII", data, 0x178 + 8, 0x300, 0x1000, 0x200, 0x200)
        mapper = helper("vaddr-to-offset.py")["parse_pe"]
        self.assertEqual(mapper(data, 0x401010), 0x210)
        self.assertEqual(mapper(data, 0x1010, True), 0x210)
        self.assertEqual(mapper(data, 0x400080), 0x80)
        self.assertIsNone(mapper(data, 0x401250))
        self.assertIsNone(mapper(data, 0x403000))

    def test_elf_mapping_respects_endianness_and_file_backing(self):
        mapper = helper("vaddr-to-offset.py")["parse_elf"]
        for endian, encoding in [("<", 1), (">", 2)]:
            data = bytearray(0x200)
            data[:6] = b"\x7fELF\x02" + bytes([encoding])
            struct.pack_into(endian + "Q", data, 0x20, 0x40)
            struct.pack_into(endian + "HH", data, 0x36, 56, 1)
            struct.pack_into(endian + "IIQQQQQQ", data, 0x40, 1, 5, 0x100, 0x400000, 0, 0x100, 0x200, 0x1000)
            self.assertEqual(mapper(data, 0x400010), 0x110)
            self.assertIsNone(mapper(data, 0x400180))

    def test_macho_segment_and_fat_mapping(self):
        functions = helper("vaddr-to-offset.py")
        data = bytearray(0x100)
        struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, 2, 1, 72, 0, 0)
        struct.pack_into("<II16sQQQQIIII", data, 32, 0x19, 72, b"__TEXT", 0x100000000, 0x100, 0, 0x100, 7, 5, 0, 0)
        self.assertEqual(functions["parse_macho"](data, 0x100000080), 0x80)
        fat = bytearray(0x200)
        struct.pack_into(">II", fat, 0, 0xCAFEBABE, 1)
        struct.pack_into(">IIIII", fat, 8, 0x01000007, 3, 0x100, 0x100, 8)
        fat[0x100:] = data
        self.assertEqual(functions["fat_slices"](fat)[0], ("x86_64", 0x100, 0x100))
        self.assertEqual(helper("find-patch-sites.py")["fat_slices"](fat), functions["fat_slices"](fat))

    def test_short_inputs_fail_cleanly(self):
        source = self.work / "short"
        source.write_bytes(b"x")
        for script, args in [("vaddr-to-offset.py", [source, "0x1"]), ("find-patch-sites.py", [source])]:
            result = self.command(script, *args)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)

    def test_installer_dry_run_and_references_are_complete_after_copy(self):
        install = helper("install-skills.py")["install"]
        target = self.work / "skills"
        install(target, True)
        self.assertFalse(target.exists())
        names = install(target)
        self.assertEqual(len(names), 12)
        workflow = target / "rea-knowledge-base" / "references" / "references" / "agent-workflow.md"
        self.assertEqual(workflow.read_bytes(), (ROOT / "references" / "agent-workflow.md").read_bytes())
        for name in names:
            text = (target / name / "SKILL.md").read_text(encoding="utf-8")
            self.assertEqual(text.count("## Required working agreement"), 1)
            self.assertIn("[Agent workflow](../rea-knowledge-base/references/references/agent-workflow.md)", text)
        check = helper("check-knowledge.py")["check_document"]
        for path in target.rglob("*.md"):
            self.assertEqual(check(path), [], str(path))
        original = target / names[0] / "SKILL.md"
        original.write_text("user customization")
        install(target)
        self.assertEqual((target / names[0] / "SKILL.md").read_text(encoding="utf-8").count("## Required working agreement"), 1)
        self.assertTrue(any(path.read_text() == "user customization" for path in (target.parent / "fujiang-rea-backups").glob("*/*/SKILL.md")))

    def test_installer_rejects_source_destination_and_symlinks(self):
        install = helper("install-skills.py")["install"]
        with self.assertRaises(ValueError):
            install(ROOT / "skills", True)
        if os.name == "nt":
            return
        target = self.work / "skills"
        target.mkdir()
        (target / "rea-native-static").symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(ValueError):
            install(target)

    def test_install_rollback_restores_existing_skill(self):
        install = helper("install-skills.py")["install"]
        target = self.work / "skills"
        existing = target / "rea-android-apps"
        existing.mkdir(parents=True)
        (existing / "SKILL.md").write_text("original customization")
        rename = Path.rename
        def fail_second_stage(source, destination):
            if source.name == "rea-anti-analysis-bypass" and source.parent.name.startswith(".rea-stage-"):
                raise OSError("fixture failure")
            return rename(source, destination)
        with patch.object(Path, "rename", fail_second_stage):
            with self.assertRaises(OSError):
                install(target)
        self.assertEqual((existing / "SKILL.md").read_text(), "original customization")

    def test_validator_detects_duplicate_keys_wrong_booleans_and_dates(self):
        functions = helper("check-knowledge.py")
        with self.assertRaises(ValueError):
            functions["parse_frontmatter"]('id: "one"\nid: "two"')
        source = next((ROOT / "knowledge" / "native-core").glob("*.md"))
        target = self.work / "native-core" / source.name
        target.parent.mkdir()
        text = source.read_text()
        target.write_text(text.replace("verified: false", "verified: 0"))
        self.assertTrue(any("boolean" in message for message in functions["check_file"](target, None, True)))
        target.write_text(text.replace('updated: "2026-11-15"', 'updated: "2026-02-30"'))
        self.assertTrue(any("calendar date" in message for message in functions["check_file"](target, None, True)))

    def test_normalization_preserves_pac_architecture_and_rejects_unknown_names(self):
        functions = helper("normalize-knowledge.py")
        self.assertEqual(functions["normalise_arch"]('"arm64e, x86_64"'), "x86-64, arm64e")
        root = self.work / "knowledge" / "native-core"
        root.mkdir(parents=True)
        (root / "bad.md").write_text('---\nplatforms: "unknown-os"\narch: "arm64"\n---\nBody\n')
        result = self.command("normalize-knowledge.py", "--root", root.parent, "--check")
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(shutil.which("cc"), "a C compiler is not installed")
    def test_interposer_compiles_without_warnings(self):
        result = subprocess.run([shutil.which("cc"), "-Wall", "-Werror", "-fsyntax-only", str(ROOT / "scripts" / "elf" / "interpose.c")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("bash"), "Bash is not installed")
    def test_shell_helpers_parse(self):
        for source in [ROOT / "install.sh", *(ROOT / "scripts").rglob("*.sh")]:
            result = subprocess.run([shutil.which("bash"), "-n", str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
