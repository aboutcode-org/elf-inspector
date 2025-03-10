# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/rust-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

import pytest


from commoncode.testcase import FileDrivenTesting
from typecode import contenttype
from scancode.cli_test_utils import check_json

from elf_inspector import binary

test_env = FileDrivenTesting()
test_env.test_data_dir = os.path.join(os.path.dirname(__file__), "data")


def test_is_executable_binary():
    elf_binary = test_env.get_test_loc("symbols/liblcms2-525547ec.so.2.0.16")
    T = contenttype.get_type(elf_binary)
    assert T.is_elf

def test_can_parse_and_demangle_rust_binary_symbols_large():
    elf_binary = test_env.get_test_loc("symbols/liblcms2-525547ec.so.2.0.16")
    parsed_elf_symbols = binary.collect_and_parse_elf_symbols(elf_binary)
    expected = test_env.get_test_loc("symbols/liblcms2-symbols.json")
    check_json(expected, parsed_elf_symbols, regen=True)
