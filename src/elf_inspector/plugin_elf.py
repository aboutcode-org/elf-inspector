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

from elf_inspector.elf import get_elf_dependencies
from elf_inspector.binary import collect_and_parse_elf_symbols

@scan_impl
class ElfScanner(ScanPlugin):
    """
    Collect the names of shared objects/libraries needed by an Elf binary file.
    Also collect symbols from the Elf binary file.
    """

    resource_attributes = dict(
        elf_dependencies=attr.ib(default=attr.Factory(list), repr=False),
        elf_symbols=attr.ib(default=attr.Factory(list), repr=False),
    )

    options = [
        PluggableCommandLineOption(
            ("--elf",),
            is_flag=True,
            default=False,
            help="Collect symbols and required dependent library names from an ELF binary file.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, elf, **kwargs):
        return elf

    def get_scanner(self, **kwargs):
        return scan_elf_symbols_needed_library


def scan_elf_symbols_needed_library(location, **kwargs):
    """
    Return a mapping of:
        elf_dependencies: list of dependenct library names needed by an elf binary file
        elf_symbols: list of binary symbols collected from the elf binary file
    """

    dependencies = list(get_elf_dependencies(location))
    elf_data = collect_and_parse_elf_symbols(location)
    elf_data["elf_dependencies"] = dependencies
    return elf_data
