# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/scancode-plugins for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path

import pytest
from commoncode.testcase import FileBasedTesting
from commoncode.testcase import FileDrivenTesting

from elf_inspector import dwarf
from elf_inspector import elf

test_data_dir = os.path.join(os.path.dirname(__file__), "data")
test_env = FileDrivenTesting()
test_env.test_data_dir = str(test_data_dir)


def get_test_file_paths(base_dir):
    """
    Return a list of test file paths under ``base_dir`` Path.
    This used to collect lists of test files.
    """
    dae = Path("dwarf_and_elf")
    return [
        str(dae / p.relative_to(base_dir))
        for p in Path(base_dir).glob("*")
        if not p.name.endswith("expected.json")
    ]


test_elf_files = get_test_file_paths(
    base_dir=os.path.join(test_data_dir, "dwarf_and_elf"))


def check_dwarf(test_file, regen=False):
    test_loc = test_env.get_test_loc(test_file)
    expected_loc = f"{test_loc}.dwarf.expected.json"
    result = [list(r) for r in dwarf.get_dwarf_cu_and_die_paths(test_loc)]
    if regen:
        with open(expected_loc, "w") as exc:
            json.dump(result, exc, indent=2)

    with open(expected_loc) as exc:
        expected = json.load(exc)

    assert result == expected


@pytest.mark.parametrize("test_file", test_elf_files)  # NOQA
def test_dwarf_get_dwarf_cu_and_die_paths(test_file):
    check_dwarf(test_file)


def check_resolved_dwarf_paths(test_file, regen=False):
    test_loc = test_env.get_test_loc(test_file)
    expected_loc = f"{test_loc}.dwarf-paths.expected.json"
    result = dwarf.get_dwarf_paths(test_loc)
    if regen:
        with open(expected_loc, "w") as exc:
            json.dump(result, exc, indent=2)

    with open(expected_loc) as exc:
        expected = json.load(exc)

    assert result == expected


@pytest.mark.parametrize("test_file", test_elf_files)  # NOQA
def test_resolved_dwarf_paths(test_file):
    check_resolved_dwarf_paths(test_file)


def check_elf(test_file, regen=False):
    test_loc = test_env.get_test_loc(test_file)
    expected_loc = f"{test_loc}.elf-deps.expected.json"
    result = list(elf.get_elf_dependencies(test_loc))
    if regen:
        with open(expected_loc, "w") as exc:
            json.dump(result, exc, indent=2)

    with open(expected_loc) as exc:
        expected = json.load(exc)

    assert result == expected


@pytest.mark.parametrize("test_file", test_elf_files)  # NOQA
def test_elf_get_elf_dependencies(test_file):
    check_elf(test_file)


class TestDwarf(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), "data")

    def test_dwarf_empty_on_non_existing_file(self):
        test_file = "dwarf_and_elf/32.fsize.chgg_DOES_NOT_EXIST"
        assert list(dwarf.get_dwarf_cu_and_die_paths(test_file)) == []

    def test_dwarf_error_on_misc_elf(self):
        test_file = "dwarf_and_elf/cpp-test.o"
        test_loc = self.get_test_loc(test_file)
        emsg1 = "File format is ambiguous"
        try:
            list(dwarf.get_dwarf_cu_and_die_paths(test_loc))
        except Exception as e:
            assert emsg1 in str(e)

    def test_dwarf_error_ssdeep_x86_64(self):
        test_file = "dwarf_and_elf/ssdeep.x86_64"
        test_loc = self.get_test_loc(test_file)
        emsg1 = "File format is ambiguous"
        try:
            list(dwarf.get_dwarf_cu_and_die_paths(test_loc))
        except Exception as e:
            assert emsg1 in str(e)

    def test_dwarf_error_amd64_exec(self):
        test_loc = self.get_test_loc("dwarf_and_elf/amd64_exec")
        emsg1 = "File format is ambiguous"
        try:
            list(dwarf.get_dwarf_cu_and_die_paths(test_loc))
        except Exception as e:
            assert emsg1 in str(e)
