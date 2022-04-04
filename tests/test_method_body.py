# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import binascii

import pytest

from dncil.cil.body import CilMethodBody
from dncil.cil.enums import CorILMethod, OpCodeValue
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token
from dncil.cil.body.reader import CilMethodBodyReaderBytes

"""
.method private hidebysig static
    void Main (
        string[] args
    ) cil managed
{
    // Header Size: 12 bytes
    // Code Size: 37 (0x25) bytes
    .maxstack 1
    .entrypoint

    .try
    {
        .try
        {
            /* 0x0000025C 7201000070   */ IL_0000: ldstr     "Hello World!"
            /* 0x00000261 280B00000A   */ IL_0005: call      void [System.Console]System.Console::WriteLine(string)
            /* 0x00000266 DE18         */ IL_000A: leave.s   IL_0024
        } // end .try
        catch [System.Runtime]System.Exception
        {
            /* 0x00000268 26           */ IL_000C: pop
            /* 0x00000269 721B000070   */ IL_000D: ldstr     "Exception occurred."
            /* 0x0000026E 280B00000A   */ IL_0012: call      void [System.Console]System.Console::WriteLine(string)
            /* 0x00000273 DE0B         */ IL_0017: leave.s   IL_0024
        } // end handler
    } // end .try
    finally
    {
        /* 0x00000275 7243000070   */ IL_0019: ldstr     "Finally occurred."
        /* 0x0000027A 280B00000A   */ IL_001E: call      void [System.Console]System.Console::WriteLine(string)
        /* 0x0000027F DC           */ IL_0023: endfinally
    } // end handler

    /* 0x00000280 2A           */ IL_0024: ret
} // end of method Program::Main
"""
method_body_fat = binascii.unhexlify(
    "1B30010025000000000000007201000070280B00000ADE1826721B000070280B00000ADE0B7243000070280B00000ADC2A000000011C0000000000000C0C000D0D000001020000001919000B00000000"
)

"""
.method public hidebysig specialname rtspecialname
    instance void .ctor () cil managed
{
    // Header Size: 1 byte
    // Code Size: 7 (0x7) bytes
    .maxstack 8

    /* 0x000002A1 02           */ IL_0000: ldarg.0
    /* 0x000002A2 280C00000A   */ IL_0001: call      instance void [System.Runtime]System.Object::.ctor()
    /* 0x000002A7 2A           */ IL_0006: ret
} // end of method Program::.ctor
"""
method_body_tiny = binascii.unhexlify("1E02280C00000A2A")


def test_invalid_header_format():
    reader = CilMethodBodyReaderBytes(b"\x00")

    with pytest.raises(MethodBodyFormatError):
        _ = CilMethodBody(reader)


def test_empty_method_body():
    reader = CilMethodBodyReaderBytes(b"")

    with pytest.raises(MethodBodyFormatError):
        _ = CilMethodBody(reader)


def test_read_tiny_header():
    reader = CilMethodBodyReaderBytes(method_body_tiny)
    body = CilMethodBody(reader)

    assert body.header_size == 0x1
    assert body.flags.TinyFormat1
    assert not body.flags.TinyFormat
    assert not body.flags.SmallFormat
    assert not body.flags.MoreSects
    assert not body.flags.FatFormat
    assert body.flags.is_tiny()
    assert body.flags.value == CorILMethod.TinyFormat1
    assert body.max_stack == 0x8
    assert body.local_var_sig_tok is None
    assert body.code_size == 0x7
    assert body.size == len(method_body_tiny)
    assert body.header_size + body.code_size == body.size
    assert body.header_size + body.code_size + body.exception_handlers_size == body.size
    assert body.get_bytes() == method_body_tiny
    assert (
        body.get_header_bytes() + body.get_instruction_bytes() + body.get_exception_handler_bytes() == method_body_tiny
    )


def test_read_tiny_header_instructions():
    reader = CilMethodBodyReaderBytes(method_body_tiny)
    body = CilMethodBody(reader)

    assert len(body.instructions) == 0x3
    assert body.instructions[0].offset == 0x1
    assert body.instructions[0].opcode.value == OpCodeValue.Ldarg_0
    assert isinstance(body.instructions[1].operand, Token)
    assert body.instructions[1].operand.table == 0xA
    assert body.instructions[1].operand.rid == 0xC
    assert body.instructions[1].get_bytes() == b"\x28\x0C\x00\x00\x0A"
    assert (
        body.instructions[1].get_opcode_bytes() + body.instructions[1].get_operand_bytes()
        == body.instructions[1].get_bytes()
    )
    assert body.instructions[2].offset == 0x7
    assert body.instructions[2].opcode.value == OpCodeValue.Ret


def test_read_fat_header():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert body.flags.FatFormat
    assert body.flags.MoreSects
    assert body.flags.InitLocals
    assert body.flags.is_fat()
    assert body.header_size == 0xC
    assert body.max_stack == 0x1
    assert body.code_size == 0x25
    assert body.size == len(method_body_fat)
    assert body.header_size + body.code_size <= body.size
    assert body.header_size + body.code_size + body.exception_handlers_size == body.size
    assert body.get_bytes() == method_body_fat
    assert (
        body.get_header_bytes() + body.get_instruction_bytes() + body.get_exception_handler_bytes() == method_body_fat
    )


def test_read_fat_header_instructions():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert len(body.instructions) == 0xB
    assert body.instructions[0].offset == body.offset + body.header_size
    assert body.instructions[0].opcode.value == OpCodeValue.Ldstr
    assert body.instructions[0].mnemonic == "ldstr"
    assert isinstance(body.instructions[1].operand, Token)
    assert body.instructions[1].operand.table == 0xA
    assert body.instructions[1].operand.rid == 0xB
    assert body.instructions[1].get_bytes() == b"\x28\x0B\x00\x00\x0A"
    assert (
        body.instructions[1].get_opcode_bytes() + body.instructions[1].get_operand_bytes()
        == body.instructions[1].get_bytes()
    )
    assert body.instructions[1].size == len(body.instructions[1].get_bytes())
    assert body.instructions[1].get_opcode_size() + body.instructions[1].get_operand_size() == body.instructions[1].size
    assert body.instructions[9].offset == 0x2F
    assert body.instructions[9].opcode.value == OpCodeValue.Endfinally


def test_read_fat_header_exception_handlers():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert len(body.exception_handlers) == 0x2
    assert body.exception_handlers[0].try_start == 0x0
    assert body.exception_handlers[0].try_end == 0xC
    assert body.exception_handlers[0].handler_start == 0xC
    assert body.exception_handlers[0].handler_end == 0x19
    assert isinstance(body.exception_handlers[0].catch_type, Token)
    assert body.exception_handlers[1].is_finally()
