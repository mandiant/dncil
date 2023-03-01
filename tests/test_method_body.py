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

"""
.method private hidebysig static 
    void Main (
        string[] args
    ) cil managed 
{
    // Header Size: 12 bytes
    // Code Size: 142 (0x8E) bytes
    // LocalVarSig Token: 0x11000001 RID: 1
    .maxstack 2
    .entrypoint
    .locals init (
        [0] int32 i,
        [1] string text
    )

    /* 0x0000025C 02           */ IL_0000: ldarg.0
    /* 0x0000025D 17           */ IL_0001: ldc.i4.1
    /* 0x0000025E 9A           */ IL_0002: ldelem.ref
    /* 0x0000025F 7201000070   */ IL_0003: ldstr     "test"
    /* 0x00000264 280F00000A   */ IL_0008: call      bool [mscorlib]System.String::op_Equality(string, string)
    /* 0x00000269 2C0C         */ IL_000D: brfalse.s IL_001B

    /* 0x0000026B 720B000070   */ IL_000F: ldstr     "Hello from test"
    /* 0x00000270 281000000A   */ IL_0014: call      void [mscorlib]System.Console::WriteLine(string)
    /* 0x00000275 2B68         */ IL_0019: br.s      IL_0083

    /* 0x00000277 02           */ IL_001B: ldarg.0
    /* 0x00000278 17           */ IL_001C: ldc.i4.1
    /* 0x00000279 9A           */ IL_001D: ldelem.ref
    /* 0x0000027A 722B000070   */ IL_001E: ldstr     "testtest"
    /* 0x0000027F 280F00000A   */ IL_0023: call      bool [mscorlib]System.String::op_Equality(string, string)
    /* 0x00000284 2C0C         */ IL_0028: brfalse.s IL_0036

    /* 0x00000286 723D000070   */ IL_002A: ldstr     "Hello from testtest"
    /* 0x0000028B 281000000A   */ IL_002F: call      void [mscorlib]System.Console::WriteLine(string)
    /* 0x00000290 2B4D         */ IL_0034: br.s      IL_0083

    /* 0x00000292 16           */ IL_0036: ldc.i4.0
    /* 0x00000293 0A           */ IL_0037: stloc.0
    /* 0x00000294 2B0E         */ IL_0038: br.s      IL_0048
    
    // loop start (head: IL_0048)
        /* 0x00000296 7265000070   */ IL_003A: ldstr     "Hello from unknown"
        /* 0x0000029B 281000000A   */ IL_003F: call      void [mscorlib]System.Console::WriteLine(string)
        /* 0x000002A0 06           */ IL_0044: ldloc.0
        /* 0x000002A1 17           */ IL_0045: ldc.i4.1
        /* 0x000002A2 58           */ IL_0046: add
        /* 0x000002A3 0A           */ IL_0047: stloc.0

        /* 0x000002A4 06           */ IL_0048: ldloc.0
        /* 0x000002A5 1F64         */ IL_0049: ldc.i4.s  100
        /* 0x000002A7 32ED         */ IL_004B: blt.s     IL_003A
    // end loop

    /* 0x000002A9 00           */ IL_004D: nop
    .try
    {
        /* 0x000002AA 02           */ IL_004E: ldarg.0
        /* 0x000002AB 17           */ IL_004F: ldc.i4.1
        /* 0x000002AC 9A           */ IL_0050: ldelem.ref
        /* 0x000002AD 281100000A   */ IL_0051: call      string [mscorlib]System.IO.File::ReadAllText(string)
        /* 0x000002B2 0B           */ IL_0056: stloc.1
        /* 0x000002B3 07           */ IL_0057: ldloc.1
        /* 0x000002B4 728B000070   */ IL_0058: ldstr     "exit"
        /* 0x000002B9 280F00000A   */ IL_005D: call      bool [mscorlib]System.String::op_Equality(string, string)
        /* 0x000002BE 2C02         */ IL_0062: brfalse.s IL_0066

        /* 0x000002C0 DE27         */ IL_0064: leave.s   IL_008D

        /* 0x000002C2 07           */ IL_0066: ldloc.1
        /* 0x000002C3 281000000A   */ IL_0067: call      void [mscorlib]System.Console::WriteLine(string)
        /* 0x000002C8 07           */ IL_006C: ldloc.1
        /* 0x000002C9 281000000A   */ IL_006D: call      void [mscorlib]System.Console::WriteLine(string)
        /* 0x000002CE 07           */ IL_0072: ldloc.1
        /* 0x000002CF 281000000A   */ IL_0073: call      void [mscorlib]System.Console::WriteLine(string)
        /* 0x000002D4 17           */ IL_0078: ldc.i4.1
        /* 0x000002D5 281200000A   */ IL_0079: call      void [mscorlib]System.Environment::Exit(int32)
        /* 0x000002DA DE03         */ IL_007E: leave.s   IL_0083
    } // end .try
    catch [mscorlib]System.Object
    {
        /* 0x000002DC 26           */ IL_0080: pop
        /* 0x000002DD DE0A         */ IL_0081: leave.s   IL_008D
    } // end handler

    /* 0x000002DF 7295000070   */ IL_0083: ldstr     "Failed"
    /* 0x000002E4 281000000A   */ IL_0088: call      void [mscorlib]System.Console::WriteLine(string)

    /* 0x000002E9 2A           */ IL_008D: ret
} // end of method Program::Main
"""
method_body_fat_complex = binascii.unhexlify(
    "1b3002008e0000000100001102179a7201000070280f00000a2c0c720b000070281000000a2b6802179a722b000070280f00000a2c0c723d000070281000000a2b4d160a2b0e7265000070281000000a0617580a061f6432ed0002179a281100000a0b07728b000070280f00000a2c02de2707281000000a07281000000a07281000000a17281200000ade0326de0a7295000070281000000a2a00000110000000004e003280000310000001"
)


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

    insn_bytes = bytes()
    for insn in body.instructions:
        insn_bytes += insn.get_bytes()

    assert insn_bytes == body.get_instruction_bytes()


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

    insn_bytes = bytes()
    for insn in body.instructions:
        insn_bytes += insn.get_bytes()

    assert insn_bytes == body.get_instruction_bytes()


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


def test_read_tiny_header_blocks():
    reader = CilMethodBodyReaderBytes(method_body_tiny)
    body = CilMethodBody(reader)
    blocks = list(body.get_basic_blocks())

    assert len(blocks) == 1
    assert blocks[0].get_bytes() == b"\x02\x28\x0C\x00\x00\x0A\x2a"
    assert blocks[0].size == 7
    assert blocks[0].instructions[-1].opcode.value == OpCodeValue.Ret

    block_bytes = b""
    for bb in blocks:
        block_bytes += bb.get_bytes()

    assert block_bytes == body.get_instruction_bytes()
    assert len(blocks[0].preds) == 0
    assert len(blocks[-1].succs) == 0


def test_read_fat_header_complex_blocks():
    reader = CilMethodBodyReaderBytes(method_body_fat_complex)
    body = CilMethodBody(reader)
    blocks = list(body.get_basic_blocks())

    assert len(blocks) == 13
    assert blocks[4].get_bytes() == b"\x16\x0a\x2b\x0e"
    assert blocks[11].size == 10
    assert blocks[11].instructions[0].opcode.value == OpCodeValue.Ldstr
    assert blocks[11].instructions[-1].opcode.value == OpCodeValue.Call

    block_bytes = b""
    for bb in blocks:
        block_bytes += bb.get_bytes()

    assert block_bytes == body.get_instruction_bytes()
    assert len(blocks[0].preds) == 0
    assert len(blocks[-1].succs) == 0
    assert len(blocks[-1].preds) == 3
    assert len(blocks[9].preds) == 1
    assert len(blocks[9].succs) == 1
    assert len(blocks[1].succs) == 1
    assert blocks[8].start_offset in [bb.start_offset for bb in blocks[-1].preds]
    assert blocks[10].start_offset in [bb.start_offset for bb in blocks[-1].preds]
    assert blocks[11].start_offset in [bb.start_offset for bb in blocks[-1].preds]
    assert blocks[7].start_offset in [bb.start_offset for bb in blocks[9].preds]
    assert blocks[7].start_offset in [bb.start_offset for bb in blocks[8].preds]
    assert blocks[9].start_offset in [bb.start_offset for bb in blocks[7].succs]
    assert blocks[8].start_offset in [bb.start_offset for bb in blocks[7].succs]
