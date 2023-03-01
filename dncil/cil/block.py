# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import List, Optional

from dncil.cil.instruction import Instruction


class BasicBlock:
    def __init__(self, instructions: Optional[List[Instruction]] = None):
        self.instructions = instructions or []
        self.preds: List[BasicBlock] = []
        self.succs: List[BasicBlock] = []

    @property
    def start_offset(self) -> int:
        return self.instructions[0].offset

    @property
    def end_offset(self) -> int:
        return self.instructions[-1].offset + self.instructions[-1].size

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset

    def get_bytes(self) -> bytes:
        block_bytes: bytes = bytes()

        for insn in self.instructions:
            block_bytes += insn.get_bytes()

        return block_bytes
