# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND LicenseRef-scancode-public-domain
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/elf-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

"""
Functions to extract information from binary Elf files DWARF debug data using
pyelftools.
Based on code by:
Eli Bendersky (eliben@gmail.com): "This code is in the public domain"
"""

import os
import posixpath

from commoncode.paths import resolve as resolve_path
from elftools.dwarf.descriptions import set_global_machine_arch
from elftools.elf.elffile import ELFFile
from typecode import contenttype


def bytes2str(b):
    """Decode a bytes object into a string."""
    return b.decode("latin-1")


def get_dwarf_paths(location, resolve=True):
    """
    Return a mapping of DWARF debug paths as:
        {compiled_paths:[...], included_paths: [....]}
    extracted from DWARFs in the ELF file at ``location``.
    Resolve and normalize paths if ``resolve`` is True.
    """
    compiled_paths = []
    included_paths = []
    for ptype, path in get_dwarf_cu_and_die_paths(location):
        if resolve:
            path = resolve_path(path)

        if ptype == "compiled_path":
            compiled_paths.append(path)
        else:
            included_paths.append(path)

    return dict(
        compiled_paths=sorted(compiled_paths),
        included_paths=sorted(included_paths),
    )


def get_dwarf_cu_and_die_paths(location):
    """
    Yield tuple of (path type, path) extracted from DWARFs in the ELF file at
    ``location``. Path type is either "compiled_path" for CU paths or
    "included_path" for indirect references to DIE paths.
    """
    if not os.path.exists(location):
        return

    T = contenttype.get_type(location)
    if (not T.is_elf) or T.is_stripped_elf:
        return

    with open(location, "rb") as inp:
        elffile = ELFFile(inp)
        if not elffile.has_dwarf_info():
            return

        dwarfinfo = elffile.get_dwarf_info()

        # warning this is a global meaning that the library may not be thread safe
        set_global_machine_arch(elffile.get_machine_arch())

        seen = set()

        for cu in dwarfinfo.iter_CUs():
            # TODO: log or return this?
            loggable = dict(
                dwarf_format=cu.structs.dwarf_format,
                dwarf_version=cu.header.version,
            )

            # The first DIE (Debug Information Entry)
            # in a CU (Compilation Unit) has the path to the compiled file.
            cu_path = None
            try:
                cu_path = cu.get_top_DIE().get_full_path()
                if cu_path and cu_path not in seen:
                    seen.add(cu_path)
                    yield "compiled_path", cu_path
            except:
                # TODO: log me
                pass

            comp_dir = get_comp_dir(cu)
            # After these we have secondary paths to other programs used
            # during compliation such as stdlib headers, etc
            try:
                for die in cu.iter_DIEs():
                    if die.is_null():
                        continue
                    for attr_name in die.attributes:
                        attr = die.attributes[attr_name]
                        if attr.name not in (
                            "DW_AT_decl_file",
                            "DW_AT_call_file",
                        ):
                            continue

                        call_path = None
                        try:
                            call_path = get_file_path(
                                file_attr=attr,
                                die=die,
                                cu=cu,
                                comp_dir=comp_dir,
                            )
                        except:
                            # TODO: log me
                            pass
                        if call_path and call_path not in seen:
                            seen.add(call_path)
                            yield "included_path", call_path
            except:
                # TODO: log me. This is due to https://github.com/eliben/pyelftools/issues/476
                pass


def get_comp_dir(cu):
    """
    Return the path of the compilation directory of ``cu`` compliation unit
    or an empty string
    """
    try:
        cutda = cu.get_top_DIE().attributes
    except:
        return ""
    comp_dir = cutda.get("DW_AT_comp_dir")
    if comp_dir:
        cdv = comp_dir.value
        return cdv and isinstance(cdv, bytes) and bytes2str(cdv) or str(cdv)
    return ""


def get_full_path(die):
    """
    Return the full path filename for the compilation unit top file.
    """
    comp_dir_attr = get_comp_dir(die.cu)

    cdav = comp_dir_attr.value if comp_dir_attr else ""
    comp_dir = bytes2str(cdav) if cdav else ""

    fname_attr = die.attributes.get("DW_AT_name")
    fav = fname_attr.value if fname_attr else ""
    fname = bytes2str(fav) if fav else ""
    return posixpath.join(comp_dir, fname)


def get_file_path(file_attr, die, cu, comp_dir):
    """
    Return the path to a compiled file or an included file in a ``die`` Debug
    Information Entry, its ``cu`` compliation and the base ``comp_dir``
    compliation directory. Return None if it cannot be collected.
    """
    if not hasattr(cu, "_lineprogram"):
        cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)

    # Filename/dirname arrays are 0 based in DWARFv5
    is_dwarf5 = cu._lineprogram.header.version >= 5
    file_index = file_attr.value if is_dwarf5 else file_attr.value - 1

    if cu._lineprogram and file_index >= 0 and file_index < len(cu._lineprogram.header.file_entry):
        file_entry = cu._lineprogram.header.file_entry[file_index]
        dir_index = file_entry.dir_index if is_dwarf5 else file_entry.dir_index - 1
        includes = cu._lineprogram.header.include_directory

        if dir_index >= 0:
            idi = includes[dir_index]
            directory = isinstance(idi, bytes) and bytes2str(idi) or str(idi)
            if directory.startswith("."):
                # TODO: this may not always be correct
                directory = posixpath.join(comp_dir, directory)
        else:
            directory = comp_dir

        fen = file_entry.name
        file_name = isinstance(fen, bytes) and bytes2str(fen) or str(fen)
        file_path = posixpath.join(directory, file_name)
        return file_path
