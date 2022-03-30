# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from dncil.cil.enums import CorILMethod


class CilMethodBodyFlags:
    """store maanged method body flags"""

    def __init__(self, flags: int):
        self.value: int = flags

        self.SmallFormat: bool = (flags & CorILMethod.FormatMask) == CorILMethod.SmallFormat
        self.TinyFormat: bool = (flags & CorILMethod.FormatMask) == CorILMethod.TinyFormat
        self.FatFormat: bool = (flags & CorILMethod.FormatMask) == CorILMethod.FatFormat
        self.TinyFormat1: bool = (flags & CorILMethod.FormatMask) == CorILMethod.TinyFormat1
        self.MoreSects: bool = bool(flags & CorILMethod.MoreSects)
        self.InitLocals: bool = bool(flags & CorILMethod.InitLocals)
        self.CompressedIL: bool = bool(flags & CorILMethod.CompressedIL)

    def __str__(self):
        def _to_print(v):
            return "true" if v else "false"

        return (
            f"SmallFormat  :  {_to_print(self.SmallFormat)}\n"
            + f"TinyFormat   :  {_to_print(self.TinyFormat)}\n"
            + f"FatFormat    :  {_to_print(self.FatFormat)}\n"
            + f"TinyFormat1  :  {_to_print(self.TinyFormat1)}\n"
            + f"MoreSects    :  {_to_print(self.MoreSects)}\n"
            + f"InitLocals   :  {_to_print(self.InitLocals)}\n"
            + f"CompressedIL :  {_to_print(self.CompressedIL)}\n"
        )

    def __repr__(self):
        return str(self)

    def is_tiny(self) -> bool:
        """check if tiny format flags set"""
        return any((self.TinyFormat, self.TinyFormat1))

    def is_fat(self) -> bool:
        """check if fat format flags set"""
        return self.FatFormat
