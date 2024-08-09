# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/elf-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import attr
from commoncode.cliutils import SCAN_GROUP
from commoncode.cliutils import PluggableCommandLineOption
from plugincode.scan import ScanPlugin
from plugincode.scan import scan_impl

from elf_inspector.dwarf import get_dwarf_paths


@scan_impl
class DwarfScanner(ScanPlugin):
    """
    Scan a dwarf infos for URLs.
    """

    resource_attributes = dict(dwarf_source_paths=attr.ib(
        default=attr.Factory(dict), repr=False))

    options = [
        PluggableCommandLineOption(
            ("--dwarf",),
            is_flag=True,
            default=False,
            help="Collect source code path from compilation units found in " "ELF DWARFs.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, dwarf, **kwargs):
        return dwarf

    def get_scanner(self, **kwargs):
        return get_dwarfs


def get_dwarfs(location, **kwargs):
    """
    Return a mapping with path to original source_files and included
    source_files.
    """
    # Collect unique paths to compiled source code found in Elf binaries DWARF
    # sections for D2D.
    return dict(dwarf_source_paths=get_dwarf_paths(location))
