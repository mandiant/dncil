# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations


class Token(object):
    """store managed token"""

    RID_MASK: int = 0x00FFFFFF
    RID_MAX: int = RID_MASK
    TABLE_SHIFT: int = 24

    def __init__(self, value: int):
        self.value: int = value

    @property
    def rid(self) -> int:
        """get token row index"""
        return self.value & Token.RID_MASK

    @property
    def table(self) -> int:
        """get token table index"""
        return self.value >> Token.TABLE_SHIFT

    def __str__(self) -> str:
        return "token(0x%08X)" % self.value

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Token) and self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)


class InvalidToken(Token):
    """store invalid managed token"""

    def __init__(self, value: int):
        super(InvalidToken, self).__init__(value)

    def __str__(self) -> str:
        return "invalid token(0x%08X)" % self.value


class StringToken(Token):
    """store string managed token"""

    def __init__(self, value: int):
        super(StringToken, self).__init__(value)

    def __str__(self) -> str:
        return "string token(0x%08X)" % self.value
