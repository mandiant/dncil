# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import argparse

from dncil.cil.body import reader
from dncil.cil.error import MethodBodyFormatError


def main(args):
    with open(args.path, "rb") as f_in:
        dn = f_in.read()

    try:
        dn_body = reader.read_method_body_from_bytes(dn)
    except MethodBodyFormatError as e:
        print(e)
        return

    for insn in dn_body.instructions:
        print(insn)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Print IL from the raw bytes of a managed method")
    parser.add_argument("path", type=str, help="Full path to file containing raw bytes of managed method")

    main(parser.parse_args())
