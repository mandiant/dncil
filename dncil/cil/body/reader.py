# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import io
import abc
import struct
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union, Callable, Optional, cast

if TYPE_CHECKING:
    from dncil.cil.opcode import OpCode

from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.local import Local
from dncil.clr.token import Token, StringToken
from dncil.cil.opcode import OpCodes, OpCodeValue, OperandType
from dncil.clr.argument import Argument
from dncil.cil.instruction import Instruction

CIL_OPCODES = OpCodes()


class CilMethodBodyReaderBase(abc.ABC):
    """abstract class for reading managed method body"""

    @abc.abstractmethod
    def read(self, n: int) -> bytes:
        """get bytes from stream"""
        ...

    @abc.abstractmethod
    def tell(self) -> int:
        """get stream offset"""
        ...

    @abc.abstractmethod
    def seek(self, rva: int) -> int:
        """jump to stream to offset"""
        ...

    def _unpack(self, data_format: str) -> Tuple[Union[int, float], bytes]:
        """unpack bytes"""
        unpack_size: int = struct.calcsize(data_format)
        unpack_bytes: bytes = self.read(unpack_size)
        if unpack_bytes == b"" or len(unpack_bytes) != unpack_size:
            raise MethodBodyFormatError(
                "not enough data while parsing method body @ offset 0x%X" % (self.tell() - len(unpack_bytes))
            )
        return struct.unpack(data_format, unpack_bytes)[0], unpack_bytes

    def is_arg_operand_instruction(self, insn: Instruction) -> bool:
        """check if instruction has a argument operand"""
        return insn.opcode.value in (
            OpCodeValue.Ldarg,
            OpCodeValue.Ldarg_S,
            OpCodeValue.Ldarga,
            OpCodeValue.Ldarga_S,
            OpCodeValue.Starg,
            OpCodeValue.Starg_S,
        )

    def read_uint8(self) -> Tuple[int, bytes]:
        """get unsigned 8-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<B"))

    def read_int8(self) -> Tuple[int, bytes]:
        """get signed 8-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<b"))

    def read_uint16(self) -> Tuple[int, bytes]:
        """get unsigned 16-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<H"))

    def read_int16(self) -> Tuple[int, bytes]:
        """get signed 16-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<h"))

    def read_uint32(self) -> Tuple[int, bytes]:
        """get unsigned 32-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<I"))

    def read_int32(self) -> Tuple[int, bytes]:
        """get signed 32-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<i"))

    def read_uint64(self) -> Tuple[int, bytes]:
        """get unsigned 64-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<Q"))

    def read_int64(self) -> Tuple[int, bytes]:
        """get signed 64-bit integer"""
        return cast(Tuple[int, bytes], self._unpack("<q"))

    def read_float32(self) -> Tuple[float, bytes]:
        """get 32-bit float"""
        return self._unpack("<f")

    def read_double64(self) -> Tuple[float, bytes]:
        """get 64-bit float"""
        return self._unpack("<d")

    def read_inline_br_target(self, insn: Instruction) -> Tuple[int, bytes]:
        """get inline branch target"""
        branch_offset: int
        branch_offset_bytes: bytes

        branch_offset, branch_offset_bytes = self.read_uint32()
        return insn.offset + insn.size + branch_offset, branch_offset_bytes

    def read_inline_field(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed field token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return Token(token_value), token_bytes

    def read_inline_i(self, insn: Instruction) -> Tuple[int, bytes]:
        """get inline 32-bit integer"""
        return self.read_uint32()

    def read_inline_i8(self, insn: Instruction) -> Tuple[int, bytes]:
        """get inline 64-bit integer"""
        return self.read_uint64()

    def read_inline_method(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed method token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return Token(token_value), token_bytes

    def read_inline_none(self, insn: Instruction) -> Tuple[None, bytes]:
        """get inline empty operand"""
        return None, b""

    def read_inline_phi(self, insn: Instruction) -> Tuple[None, bytes]:
        """get inline empty operand"""
        return None, b""

    def read_inline_r(self, insn: Instruction) -> Tuple[float, bytes]:
        """get inline 64-bit float"""
        return self.read_double64()

    def read_inline_sig(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed signature token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return Token(token_value), token_bytes

    def read_inline_string(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed string token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return StringToken(token_value), token_bytes

    def read_inline_switch(self, insn: Instruction) -> Tuple[list, bytes]:
        """get inline switch + branch targets"""
        num_branches: int
        branches_bytes: bytes

        num_branches, branches_bytes = self.read_uint32()
        offset_after_insn: int = insn.offset + insn.opcode.size + 4 + num_branches * 4

        branches: List[int] = []
        for _ in range(num_branches):
            branch_offset: int
            branch_offset_raw: bytes

            branch_offset, branch_offset_raw = self.read_uint32()
            branches.append(offset_after_insn + branch_offset)
            branches_bytes += branch_offset_raw

        return branches, branches_bytes

    def read_inline_tok(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return Token(token_value), token_bytes

    def read_inline_type(self, insn: Instruction) -> Tuple[Token, bytes]:
        """get inline managed type token"""
        token_value: int
        token_bytes: bytes

        token_value, token_bytes = self.read_uint32()
        return Token(token_value), token_bytes

    def read_inline_var(self, insn: Instruction) -> Tuple[Union[Local, Argument], bytes]:
        """get inline managed method argument index or managed method local index"""
        var_value: int
        var_bytes: bytes
        var_obj: Union[Local, Argument]

        var_value, var_bytes = self.read_uint16()
        if self.is_arg_operand_instruction(insn):
            var_obj = Argument(var_value)
        else:
            var_obj = Local(var_value)

        return var_obj, var_bytes

    def read_short_inline_br_target(self, insn: Instruction) -> Tuple[int, bytes]:
        """get inline branch target"""
        branch_offset: int
        branch_offset_bytes: bytes

        branch_offset, branch_offset_bytes = self.read_uint8()
        return insn.offset + insn.size + branch_offset, branch_offset_bytes

    def read_short_inline_i(self, insn: Instruction) -> Tuple[int, bytes]:
        """get inline 8-bit integer"""
        if insn.opcode.value == OpCodeValue.Ldc_I4_S:
            # signed byte
            return self.read_int8()
        # unsigned byte
        return self.read_uint8()

    def read_short_inline_r(self, insn: Instruction) -> Tuple[float, bytes]:
        """get inline 32-bit float"""
        return self.read_float32()

    def read_short_inline_var(self, insn: Instruction) -> Tuple[Union[Local, Argument], bytes]:
        """get inline managed method argument index or managed method local index"""
        var_value: int
        var_bytes: bytes
        var_obj: Union[Local, Argument]

        var_value, var_bytes = self.read_uint8()
        if self.is_arg_operand_instruction(insn):
            var_obj = Argument(var_value)
        else:
            var_obj = Local(var_value)

        return var_obj, var_bytes

    def read_instruction(self, off: int = 0) -> Instruction:
        """get instruction"""
        insn: Instruction = Instruction()

        insn.offset = off
        insn.opcode, insn.opcode_bytes = self.read_opcode()
        insn.operand, insn.operand_bytes = self.read_operand(insn)

        return insn

    def read_opcode(self) -> Tuple[OpCode, bytes]:
        """get instruction opcode"""
        op_value_first: int
        op_byte_first: bytes

        op_value_second: int
        op_byte_second: bytes

        opcode: OpCode
        opcode_bytes: bytes

        op_value_first, op_byte_first = self.read_uint8()

        if op_value_first == 0xFE:
            # 2-byte opcode
            op_value_second, op_byte_second = self.read_uint8()
            try:
                opcode = CIL_OPCODES.two_byte_op_codes[op_value_second]
                opcode_bytes = op_byte_first + op_byte_second
            except IndexError:
                raise MethodBodyFormatError("bad opcode %02X%02X" % (op_value_first, op_value_second))
        else:
            # 1-byte opcode
            try:
                opcode = CIL_OPCODES.one_byte_op_codes[op_value_first]
                opcode_bytes = op_byte_first
            except IndexError:
                raise MethodBodyFormatError("bad opcode %02X" % op_value_first)

        return opcode, opcode_bytes

    def read_operand(self, insn: Instruction) -> Tuple[Union[Token, Local, Argument, list, float, int, None], bytes]:
        """get instruction operand"""
        readers: Dict[OperandType, Callable] = {
            OperandType.InlineBrTarget: self.read_inline_br_target,
            OperandType.InlineField: self.read_inline_field,
            OperandType.InlineI: self.read_inline_i,
            OperandType.InlineI8: self.read_inline_i8,
            OperandType.InlineMethod: self.read_inline_method,
            OperandType.InlineNone: self.read_inline_none,
            OperandType.InlinePhi: self.read_inline_phi,
            OperandType.InlineR: self.read_inline_r,
            OperandType.InlineSig: self.read_inline_sig,
            OperandType.InlineString: self.read_inline_string,
            OperandType.InlineSwitch: self.read_inline_switch,
            OperandType.InlineTok: self.read_inline_tok,
            OperandType.InlineType: self.read_inline_type,
            OperandType.InlineVar: self.read_inline_var,
            OperandType.ShortInlineBrTarget: self.read_short_inline_br_target,
            OperandType.ShortInlineI: self.read_short_inline_i,
            OperandType.ShortInlineR: self.read_short_inline_r,
            OperandType.ShortInlineVar: self.read_short_inline_var,
        }
        reader: Optional[Callable] = readers.get(insn.opcode.operand_type, None)

        if reader is None:
            raise MethodBodyFormatError("bad operand type 0x%02X" % insn.opcode.operand_type)

        return reader(insn)


class CilMethodBodyReaderBytes(CilMethodBodyReaderBase):
    """bytestream impl for abstract CilMethodBodyReaderBase"""

    def __init__(self, bs: bytes):
        self.stream: io.BytesIO = io.BytesIO(bs)

    def read(self, n: int) -> bytes:
        return self.stream.read(n)

    def tell(self) -> int:
        return self.stream.tell()

    def seek(self, loc: int) -> int:
        return self.stream.seek(loc)


def read_method_body_from_bytes(bio: bytes) -> CilMethodBody:
    """read managed method body from byte stream"""
    return CilMethodBody(CilMethodBodyReaderBytes(bio))
