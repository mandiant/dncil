# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Set, Dict, List, Iterator, Optional, cast

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body.reader import CilMethodBodyReaderBase

from dncil.cil.block import BasicBlock
from dncil.cil.enums import CorILMethod, CorILMethodSect
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token
from dncil.cil.exception import ExceptionHandler
from dncil.cil.body.flags import CilMethodBodyFlags
from dncil.cil.instruction import Instruction


class CilMethodBody:
    """store managed method body"""

    def __init__(self, reader: CilMethodBodyReaderBase):
        self.offset: int
        self.header_size: int
        self.flags: CilMethodBodyFlags
        self.max_stack: int
        self.code_size: int
        self.local_var_sig_tok: Optional[Token]
        self.size: int
        self.raw_bytes: bytes
        self.exception_handlers_size: int

        self.instructions: List[Instruction] = []
        self.basic_blocks: List[BasicBlock] = []
        self.exception_handlers: List[ExceptionHandler] = []

        # set method offset
        self.offset = reader.tell()

        # parse the method body
        self.parse_header(reader)
        self.parse_instructions(reader)
        self.parse_exception_handlers(reader)

        # use initial offset + method body size to read method body bytes (not the most efficient)
        final_pos = reader.tell()
        reader.seek(self.offset)
        self.raw_bytes = reader.read(self.size)
        reader.seek(final_pos)

        # calculate exception handlers size
        self.exception_handlers_size = self.size - self.header_size - self.code_size

    def __int__(self) -> int:
        return self.offset

    def get_bytes(self) -> bytes:
        """get method body bytes"""
        return self.raw_bytes

    def get_header_bytes(self) -> bytes:
        """get method header bytes"""
        return self.raw_bytes[: self.header_size]

    def get_instruction_bytes(self) -> bytes:
        """get method instruction bytes"""
        return self.raw_bytes[self.header_size : self.header_size + self.code_size]

    def get_exception_handler_bytes(self) -> bytes:
        """get method exception handler bytes"""
        return self.raw_bytes[self.header_size + self.code_size :]

    def get_basic_blocks(self) -> Iterator[BasicBlock]:
        if not self.basic_blocks:
            self.parse_basic_blocks()
        yield from self.basic_blocks

    def parse_header(self, reader: CilMethodBodyReaderBase):
        """get method body header"""
        # header byte gives us the format and, in fat format, implementation flags used at runtime
        header_byte: int = reader.read_uint8()[0]
        if header_byte & CorILMethod.FormatMask in (CorILMethod.TinyFormat, CorILMethod.TinyFormat1):
            # tiny format - use default values specified by ECMA for all fields other than code size
            self.flags = CilMethodBodyFlags(header_byte & CorILMethod.FormatMask)
            self.header_size = 1
            self.max_stack = 8
            self.code_size = header_byte >> 2
            self.local_var_sig_tok = None
        elif header_byte & CorILMethod.FormatMask in (CorILMethod.FatFormat,):
            # fat format
            self.flags = CilMethodBodyFlags((reader.read_uint8()[0] << 8) | header_byte)
            self.header_size = self.flags.value >> 12
            self.max_stack = reader.read_uint16()[0]
            self.code_size = reader.read_uint32()[0]

            local_var_sig_tok = reader.read_uint32()[0]
            if local_var_sig_tok == 0:
                # zero indicates there are no local variables
                self.local_var_sig_tok = None
            else:
                self.local_var_sig_tok = Token(local_var_sig_tok)

            # ECMA states fat format size is "currently" 3; we may need to change this calculation if that ever changes
            reader.seek(reader.tell() - 12 + self.header_size * 4)

            # unsure on this check - may be some edge case handled by dnlib
            if self.header_size < 3:
                self.flags.value &= 0xFFF7

            # size indicates the number of 32-bit integers so we need to calc the total number of bytes
            self.header_size *= 4
        else:
            raise MethodBodyFormatError("bad header format 0x%02X" % (header_byte & CorILMethod.FormatMask))

    def parse_instructions(self, reader: CilMethodBodyReaderBase):
        """get CIL instructions"""
        current_offset: int = self.offset + self.header_size
        code_end_offset: int = reader.tell() + self.code_size

        # instructions are stored sequentially so we just read through the stream
        while reader.tell() < code_end_offset:
            insn: Instruction = reader.read_instruction(current_offset)
            current_offset += insn.size
            self.instructions.append(insn)

    def parse_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers"""
        if not self.flags.MoreSects:
            # exception handlers are stored in extra data sections so bail if there are none
            self.size = reader.tell() - self.offset
            return

        # extra data sections start at first 4-byte boundary
        reader.seek((reader.tell() + 3) & ~3)

        # header byte gives us the format
        header_byte: int = reader.read_uint8()[0]

        # unsure on this check - may be some edge case handler by dnlib
        if header_byte & CorILMethodSect.KindMask != 1:
            self.size = reader.tell() - self.offset
            return

        if header_byte & CorILMethodSect.FatFormat:
            # fat format
            self.parse_fat_exception_handlers(reader)
        else:
            # tiny format
            self.parse_tiny_exception_handlers(reader)

        self.size = reader.tell() - self.offset

    def parse_fat_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers in fat format"""
        # fat header is 8 bits (flags) + 24 bits (size) so to get the size we rewind 8 bits, read a 32-bit integer, and shift for the 24-bit integer
        reader.seek(reader.tell() - 1)
        total_size: int = reader.read_uint32()[0] >> 8

        # size is total bytes so we need to calc the number of exception handlers
        num_exceptions: int = total_size // ExceptionHandler.FAT_SIZE
        for _ in range(num_exceptions):
            eh: ExceptionHandler = ExceptionHandler(reader.read_uint32()[0])

            eh.try_start = reader.read_uint32()[0]
            eh.try_end = eh.try_start + reader.read_uint32()[0]

            eh.handler_start = reader.read_uint32()[0]
            eh.handler_end = eh.handler_start + reader.read_uint32()[0]

            if eh.is_catch():
                eh.catch_type = Token(reader.read_uint32()[0])
            elif eh.is_filter():
                eh.filter_start = reader.read_uint32()[0]
            else:
                _ = reader.read_uint32()[0]

            self.exception_handlers.append(eh)

    def parse_tiny_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers in tiny format"""
        # size is total bytes so we need to calc the number of exception handlers
        num_exceptions: int = reader.read_uint8()[0] // ExceptionHandler.TINY_SIZE

        # skip padding (16 bits)
        reader.seek(reader.tell() + 2)

        for _ in range(num_exceptions):
            eh: ExceptionHandler = ExceptionHandler(reader.read_uint16()[0])

            eh.try_start = reader.read_uint16()[0]
            eh.try_end = eh.try_start + reader.read_uint8()[0]

            eh.handler_start = reader.read_uint16()[0]
            eh.handler_end = eh.handler_start + reader.read_uint8()[0]

            if eh.is_catch():
                eh.catch_type = Token(reader.read_uint32()[0])
            elif eh.is_filter():
                eh.filter_start = reader.read_uint32()[0]
            else:
                _ = reader.read_uint32()[0]

            self.exception_handlers.append(eh)

    def parse_basic_blocks(self):
        # calculate basic block leaders where,
        #   1. The first instruction of the intermediate code is a leader
        #   2. Instructions that are targets of unconditional or conditional jump/goto statements are leaders
        #   3. Instructions that immediately follow unconditional or conditional jump/goto statements are considered leaders
        #   https://www.geeksforgeeks.org/basic-blocks-in-compiler-design/

        leaders: Set[int] = set()
        for idx, insn in enumerate(self.instructions):
            if idx == 0:
                # add #1
                leaders.add(insn.offset)

            if any((insn.is_br(), insn.is_cond_br(), insn.is_leave())):
                # add #2
                leaders.add(cast(int, insn.operand))
                # add #3
                try:
                    leaders.add(self.instructions[idx + 1].offset)
                except IndexError:
                    # end of method
                    continue

        # build basic blocks using leaders
        bb_curr: Optional[BasicBlock] = None
        for idx, insn in enumerate(self.instructions):
            if insn.offset in leaders:
                # new leader, new basic block
                bb_curr = BasicBlock(instructions=[insn])
                self.basic_blocks.append(bb_curr)
                continue

            assert bb_curr is not None
            bb_curr.instructions.append(insn)

        # create mapping of first instruction to basic block
        bb_map: Dict[int, BasicBlock] = {}
        for bb in self.basic_blocks:
            bb_map[bb.start_offset] = bb

        # connect basic blocks
        for idx, bb in enumerate(self.basic_blocks):
            last = bb.instructions[-1]

            # connect branches to other basic blocks
            if any((last.is_br(), last.is_cond_br(), last.is_leave())):
                bb_branch: Optional[BasicBlock] = bb_map.get(cast(int, last.operand), None)
                if bb_branch is not None:
                    # invalid branch, may be seen in obfuscated IL
                    bb.succs.append(bb_branch)
                    bb_branch.preds.append(bb)

            if any((last.is_br(), last.is_leave())):
                # no fallthrough
                continue

            # connect fallthrough
            try:
                bb_next: BasicBlock = self.basic_blocks[idx + 1]
                bb.succs.append(bb_next)
                bb_next.preds.append(bb)
            except IndexError:
                # end of method
                continue
