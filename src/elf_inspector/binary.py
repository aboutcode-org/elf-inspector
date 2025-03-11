# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND LicenseRef-scancode-public-domain
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/elf-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from bids.analyser import BIDSAnalyser


def collect_and_parse_elf_symbols(location, include_stdlib=False, sort_symbols=True, **kwargs):
    """
    Return a list of ELF symbols of interest for the ELF binary file at ``location``.
    Return an empty list if there is no symbols or if this is not a binary.
    """
    # This should have been ``exclude_symbol`` as these
    # options give us only the symbols without deps/callgraph.
    options = {
        "dependency": True,
        "symbol": False,
        "callgraph": True,
    }
    analyser = BIDSAnalyser(options)
    analyser.analyse(location)
    elf_symbols = analyser.get_local_symbols()

    if include_stdlib:
        elf_symbols += analyser.get_global_symbols()

    if sort_symbols:
        elf_symbols = sorted(elf_symbols)

    return {"elf_symbols": elf_symbols}
