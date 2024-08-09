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


@scan_impl
class ElfScanner(ScanPlugin):
    """
    Collect the names of shared objects/libraries needed by an Elf binary file.
    """

    resource_attributes = dict(
        elf_dependencies=attr.ib(default=attr.Factory(list), repr=False),
    )

    options = [
        PluggableCommandLineOption(
            ("--elf",),
            is_flag=True,
            default=False,
            help="Collect dependent library names needed by an ELF binary file.",
            help_group=SCAN_GROUP,
            sort_order=100,
        ),
    ]

    def is_enabled(self, elf, **kwargs):
        return elf

    def get_scanner(self, **kwargs):
        return scan_elf_needed_library


def scan_elf_needed_library(location, **kwargs):
    """
    Return a mapping of elf_dependencies: list of of
    """

    results = [enl for enl in get_elf_dependencies(location)]
    return dict(elf_dependencies=results)
