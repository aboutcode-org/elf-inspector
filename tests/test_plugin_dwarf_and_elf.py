# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/scancode-plugins for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from commoncode.testcase import FileBasedTesting
from scancode.cli_test_utils import check_json_scan
from scancode.cli_test_utils import run_scan_click


class TestElfDwarfPluginScan(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), "data")

    def test_elf_plugin(self):
        test_dir = self.get_test_loc("dwarf_and_elf/exe_solaris32_cc.elf")
        result_file = self.get_temp_file("json")
        args = ["--elf", test_dir, "--json", result_file]
        run_scan_click(args)
        test_loc = self.get_test_loc("elf_dependencies-expected.json")
        check_json_scan(test_loc, result_file, regen=False)

    def test_dwarf_plugin(self):
        test_dir = self.get_test_loc("dwarf_and_elf/exe_solaris32_cc.elf")
        result_file = self.get_temp_file("json")
        args = ["--dwarf", test_dir, "--json", result_file]
        run_scan_click(args)
        test_loc = self.get_test_loc("dwarf_paths-expected.json")
        check_json_scan(test_loc, result_file, regen=False)
