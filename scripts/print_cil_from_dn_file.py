# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import argparse

import dnfile
from dnfile.enums import MetadataTables

from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

# hack to map token indexes back to dnfile tables
DN_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


class DnMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe: dnfile.dnPE, row: dnfile.mdtable.MethodDefRow):
        """ """
        self.pe = pe
        self.rva = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        """ """
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.rva), n)
        self.rva += n
        return data

    def tell(self):
        """ """
        return self.rva

    def seek(self, rva):
        """ """
        self.rva = rva

    def get_token(self, value, is_str=False):
        """ """
        token = Token(value)

        if is_str:
            return self.pe.net.user_strings.get_us(token.rid).value

        table_name = DN_META_TABLES_BY_INDEX.get(token.table, "")
        if not table_name:
            # table_index is not valid
            return InvalidToken(token.value)

        table = getattr(self.pe.net.mdtables, table_name, None)
        if table is None:
            # table index is valid but table is not present
            return InvalidToken(token.value)

        try:
            return table.rows[token.rid - 1]
        except IndexError:
            # table index is valid but row index is not valid
            return InvalidToken(token.value)


def read_method_body_from_row(dn, row):
    return CilMethodBody(DnMethodBodyReader(dn, row))


def format_operand(op):
    if isinstance(op, str):
        return f'"{op}"'
    elif isinstance(op, int):
        return hex(op)
    elif isinstance(op, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in op])}]"
    elif isinstance(op, dnfile.mdtable.MemberRefRow) and not isinstance(op.Class.row, dnfile.mdtable.TypeSpecRow):
        return f"{str(op.Class.row.TypeNamespace)}.{op.Class.row.TypeName}::{op.Name}"
    elif isinstance(op, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{op.Name}"
    else:
        return "" if op is None else str(op)


def main(args):
    dn = dnfile.dnPE(args.path)

    for row in dn.net.mdtables.MethodDef:
        # loop through each row of MethodDef table and attempt to print IL

        if not row.ImplFlags.miIL:
            # we can only display IL methods
            continue

        try:
            # attempt to read method body
            body = read_method_body_from_row(dn, row)
        except MethodBodyFormatError as e:
            print(e)
            continue

        if not body.instructions:
            # no IL to print
            continue

        print(f"\nMethod: {row.Name}")
        for insn in body.instructions:
            print(
                "{:04X}".format(insn.offset)
                + "    "
                + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                + f"{str(insn.opcode) : <15}"
                + format_operand(insn.operand)
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Print IL from the managed methods of a .NET binary")
    parser.add_argument("path", type=str, help="Full path to .NET binary")

    main(parser.parse_args())
