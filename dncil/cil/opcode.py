# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import inspect
from typing import List

from dncil.cil.enums import *


class OpCode:
    """store managed opcode"""

    def __init__(
        self,
        name: str,
        value: OpCodeValue,
        operand_type: OperandType,
        flow_control: FlowControl,
        op_code_type: OpCodeType,
        stack_push: StackBehaviour,
        stack_pop: StackBehaviour,
    ):
        self.name: str = name
        self.value: OpCodeValue = value
        self.operand_type: OperandType = operand_type
        self.flow_control: FlowControl = flow_control
        self.op_code_type: OpCodeType = op_code_type
        self.stack_push: StackBehaviour = stack_push
        self.stack_pop: StackBehaviour = stack_pop

    @property
    def size(self) -> int:
        """get opcode size"""
        return 1 if self.value < 0x100 or self.value == OpCodeValue.UNKNOWN1 else 2

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return str(self)


class OpCodes:
    """store valid opcodes - see https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/OpCodes.cs"""

    UNKNOWN1 = OpCode(
        "UNKNOWN1",
        OpCodeValue.UNKNOWN1,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    UNKNOWN2 = OpCode(
        "UNKNOWN2",
        OpCodeValue.UNKNOWN2,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Nop = OpCode(
        "nop",
        OpCodeValue.Nop,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Break = OpCode(
        "break",
        OpCodeValue.Break,
        OperandType.InlineNone,
        FlowControl.Break,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Ldarg_0 = OpCode(
        "ldarg.0",
        OpCodeValue.Ldarg_0,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldarg_1 = OpCode(
        "ldarg.1",
        OpCodeValue.Ldarg_1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldarg_2 = OpCode(
        "ldarg.2",
        OpCodeValue.Ldarg_2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldarg_3 = OpCode(
        "ldarg.3",
        OpCodeValue.Ldarg_3,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloc_0 = OpCode(
        "ldloc.0",
        OpCodeValue.Ldloc_0,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloc_1 = OpCode(
        "ldloc.1",
        OpCodeValue.Ldloc_1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloc_2 = OpCode(
        "ldloc.2",
        OpCodeValue.Ldloc_2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloc_3 = OpCode(
        "ldloc.3",
        OpCodeValue.Ldloc_3,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Stloc_0 = OpCode(
        "stloc.0",
        OpCodeValue.Stloc_0,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Stloc_1 = OpCode(
        "stloc.1",
        OpCodeValue.Stloc_1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Stloc_2 = OpCode(
        "stloc.2",
        OpCodeValue.Stloc_2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Stloc_3 = OpCode(
        "stloc.3",
        OpCodeValue.Stloc_3,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Ldarg_S = OpCode(
        "ldarg.s",
        OpCodeValue.Ldarg_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldarga_S = OpCode(
        "ldarga.s",
        OpCodeValue.Ldarga_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Starg_S = OpCode(
        "starg.s",
        OpCodeValue.Starg_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Ldloc_S = OpCode(
        "ldloc.s",
        OpCodeValue.Ldloc_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloca_S = OpCode(
        "ldloca.s",
        OpCodeValue.Ldloca_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Stloc_S = OpCode(
        "stloc.s",
        OpCodeValue.Stloc_S,
        OperandType.ShortInlineVar,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Ldnull = OpCode(
        "ldnull",
        OpCodeValue.Ldnull,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushref,
        StackBehaviour.Pop0,
    )
    Ldc_I4_M1 = OpCode(
        "ldc.i4.m1",
        OpCodeValue.Ldc_I4_M1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_0 = OpCode(
        "ldc.i4.0",
        OpCodeValue.Ldc_I4_0,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_1 = OpCode(
        "ldc.i4.1",
        OpCodeValue.Ldc_I4_1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_2 = OpCode(
        "ldc.i4.2",
        OpCodeValue.Ldc_I4_2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_3 = OpCode(
        "ldc.i4.3",
        OpCodeValue.Ldc_I4_3,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_4 = OpCode(
        "ldc.i4.4",
        OpCodeValue.Ldc_I4_4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_5 = OpCode(
        "ldc.i4.5",
        OpCodeValue.Ldc_I4_5,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_6 = OpCode(
        "ldc.i4.6",
        OpCodeValue.Ldc_I4_6,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_7 = OpCode(
        "ldc.i4.7",
        OpCodeValue.Ldc_I4_7,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_8 = OpCode(
        "ldc.i4.8",
        OpCodeValue.Ldc_I4_8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4_S = OpCode(
        "ldc.i4.s",
        OpCodeValue.Ldc_I4_S,
        OperandType.ShortInlineI,
        FlowControl.Next,
        OpCodeType.Macro,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I4 = OpCode(
        "ldc.i4",
        OpCodeValue.Ldc_I4,
        OperandType.InlineI,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldc_I8 = OpCode(
        "ldc.i8",
        OpCodeValue.Ldc_I8,
        OperandType.InlineI8,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop0,
    )
    Ldc_R4 = OpCode(
        "ldc.r4",
        OpCodeValue.Ldc_R4,
        OperandType.ShortInlineR,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr4,
        StackBehaviour.Pop0,
    )
    Ldc_R8 = OpCode(
        "ldc.r8",
        OpCodeValue.Ldc_R8,
        OperandType.InlineR,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr8,
        StackBehaviour.Pop0,
    )
    Dup = OpCode(
        "dup",
        OpCodeValue.Dup,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1_push1,
        StackBehaviour.Pop1,
    )
    Pop = OpCode(
        "pop",
        OpCodeValue.Pop,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Jmp = OpCode(
        "jmp",
        OpCodeValue.Jmp,
        OperandType.InlineMethod,
        FlowControl.Call,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Call = OpCode(
        "call",
        OpCodeValue.Call,
        OperandType.InlineMethod,
        FlowControl.Call,
        OpCodeType.Primitive,
        StackBehaviour.Varpush,
        StackBehaviour.Varpop,
    )
    Calli = OpCode(
        "calli",
        OpCodeValue.Calli,
        OperandType.InlineSig,
        FlowControl.Call,
        OpCodeType.Primitive,
        StackBehaviour.Varpush,
        StackBehaviour.Varpop,
    )
    Ret = OpCode(
        "ret",
        OpCodeValue.Ret,
        OperandType.InlineNone,
        FlowControl.Return,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Varpop,
    )
    Br_S = OpCode(
        "br.s",
        OpCodeValue.Br_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Brfalse_S = OpCode(
        "brfalse.s",
        OpCodeValue.Brfalse_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Brtrue_S = OpCode(
        "brtrue.s",
        OpCodeValue.Brtrue_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Beq_S = OpCode(
        "beq.s",
        OpCodeValue.Beq_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bge_S = OpCode(
        "bge.s",
        OpCodeValue.Bge_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bgt_S = OpCode(
        "bgt.s",
        OpCodeValue.Bgt_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Ble_S = OpCode(
        "ble.s",
        OpCodeValue.Ble_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Blt_S = OpCode(
        "blt.s",
        OpCodeValue.Blt_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bne_Un_S = OpCode(
        "bne.un.s",
        OpCodeValue.Bne_Un_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bge_Un_S = OpCode(
        "bge.un.s",
        OpCodeValue.Bge_Un_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bgt_Un_S = OpCode(
        "bgt.un.s",
        OpCodeValue.Bgt_Un_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Ble_Un_S = OpCode(
        "ble.un.s",
        OpCodeValue.Ble_Un_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Blt_Un_S = OpCode(
        "blt.un.s",
        OpCodeValue.Blt_Un_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Br = OpCode(
        "br",
        OpCodeValue.Br,
        OperandType.InlineBrTarget,
        FlowControl.Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Brfalse = OpCode(
        "brfalse",
        OpCodeValue.Brfalse,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Brtrue = OpCode(
        "brtrue",
        OpCodeValue.Brtrue,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Beq = OpCode(
        "beq",
        OpCodeValue.Beq,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bge = OpCode(
        "bge",
        OpCodeValue.Bge,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bgt = OpCode(
        "bgt",
        OpCodeValue.Bgt,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Ble = OpCode(
        "ble",
        OpCodeValue.Ble,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Blt = OpCode(
        "blt",
        OpCodeValue.Blt,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bne_Un = OpCode(
        "bne.un",
        OpCodeValue.Bne_Un,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bge_Un = OpCode(
        "bge.un",
        OpCodeValue.Bge_Un,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Bgt_Un = OpCode(
        "bgt.un",
        OpCodeValue.Bgt_Un,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Ble_Un = OpCode(
        "ble.un",
        OpCodeValue.Ble_Un,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Blt_Un = OpCode(
        "blt.un",
        OpCodeValue.Blt_Un,
        OperandType.InlineBrTarget,
        FlowControl.Cond_Branch,
        OpCodeType.Macro,
        StackBehaviour.Push0,
        StackBehaviour.Pop1_pop1,
    )
    Switch = OpCode(
        "switch",
        OpCodeValue.Switch,
        OperandType.InlineSwitch,
        FlowControl.Cond_Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Ldind_I1 = OpCode(
        "ldind.i1",
        OpCodeValue.Ldind_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_U1 = OpCode(
        "ldind.u1",
        OpCodeValue.Ldind_U1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_I2 = OpCode(
        "ldind.i2",
        OpCodeValue.Ldind_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_U2 = OpCode(
        "ldind.u2",
        OpCodeValue.Ldind_U2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_I4 = OpCode(
        "ldind.i4",
        OpCodeValue.Ldind_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_U4 = OpCode(
        "ldind.u4",
        OpCodeValue.Ldind_U4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_I8 = OpCode(
        "ldind.i8",
        OpCodeValue.Ldind_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Popi,
    )
    Ldind_I = OpCode(
        "ldind.i",
        OpCodeValue.Ldind_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Ldind_R4 = OpCode(
        "ldind.r4",
        OpCodeValue.Ldind_R4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr4,
        StackBehaviour.Popi,
    )
    Ldind_R8 = OpCode(
        "ldind.r8",
        OpCodeValue.Ldind_R8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr8,
        StackBehaviour.Popi,
    )
    Ldind_Ref = OpCode(
        "ldind.ref",
        OpCodeValue.Ldind_Ref,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushref,
        StackBehaviour.Popi,
    )
    Stind_Ref = OpCode(
        "stind.ref",
        OpCodeValue.Stind_Ref,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Stind_I1 = OpCode(
        "stind.i1",
        OpCodeValue.Stind_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Stind_I2 = OpCode(
        "stind.i2",
        OpCodeValue.Stind_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Stind_I4 = OpCode(
        "stind.i4",
        OpCodeValue.Stind_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Stind_I8 = OpCode(
        "stind.i8",
        OpCodeValue.Stind_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi8,
    )
    Stind_R4 = OpCode(
        "stind.r4",
        OpCodeValue.Stind_R4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popr4,
    )
    Stind_R8 = OpCode(
        "stind.r8",
        OpCodeValue.Stind_R8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popr8,
    )
    Add = OpCode(
        "add",
        OpCodeValue.Add,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Sub = OpCode(
        "sub",
        OpCodeValue.Sub,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Mul = OpCode(
        "mul",
        OpCodeValue.Mul,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Div = OpCode(
        "div",
        OpCodeValue.Div,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Div_Un = OpCode(
        "div.un",
        OpCodeValue.Div_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Rem = OpCode(
        "rem",
        OpCodeValue.Rem,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Rem_Un = OpCode(
        "rem.un",
        OpCodeValue.Rem_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    And = OpCode(
        "and",
        OpCodeValue.And,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Or = OpCode(
        "or",
        OpCodeValue.Or,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Xor = OpCode(
        "xor",
        OpCodeValue.Xor,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Shl = OpCode(
        "shl",
        OpCodeValue.Shl,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Shr = OpCode(
        "shr",
        OpCodeValue.Shr,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Shr_Un = OpCode(
        "shr.un",
        OpCodeValue.Shr_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Neg = OpCode(
        "neg",
        OpCodeValue.Neg,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1,
    )
    Not = OpCode(
        "not",
        OpCodeValue.Not,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1,
    )
    Conv_I1 = OpCode(
        "conv.i1",
        OpCodeValue.Conv_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_I2 = OpCode(
        "conv.i2",
        OpCodeValue.Conv_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_I4 = OpCode(
        "conv.i4",
        OpCodeValue.Conv_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_I8 = OpCode(
        "conv.i8",
        OpCodeValue.Conv_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Conv_R4 = OpCode(
        "conv.r4",
        OpCodeValue.Conv_R4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr4,
        StackBehaviour.Pop1,
    )
    Conv_R8 = OpCode(
        "conv.r8",
        OpCodeValue.Conv_R8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr8,
        StackBehaviour.Pop1,
    )
    Conv_U4 = OpCode(
        "conv.u4",
        OpCodeValue.Conv_U4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_U8 = OpCode(
        "conv.u8",
        OpCodeValue.Conv_U8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Callvirt = OpCode(
        "callvirt",
        OpCodeValue.Callvirt,
        OperandType.InlineMethod,
        FlowControl.Call,
        OpCodeType.Objmodel,
        StackBehaviour.Varpush,
        StackBehaviour.Varpop,
    )
    Cpobj = OpCode(
        "cpobj",
        OpCodeValue.Cpobj,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Ldobj = OpCode(
        "ldobj",
        OpCodeValue.Ldobj,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push1,
        StackBehaviour.Popi,
    )
    Ldstr = OpCode(
        "ldstr",
        OpCodeValue.Ldstr,
        OperandType.InlineString,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushref,
        StackBehaviour.Pop0,
    )
    Newobj = OpCode(
        "newobj",
        OpCodeValue.Newobj,
        OperandType.InlineMethod,
        FlowControl.Call,
        OpCodeType.Objmodel,
        StackBehaviour.Pushref,
        StackBehaviour.Varpop,
    )
    Castclass = OpCode(
        "castclass",
        OpCodeValue.Castclass,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushref,
        StackBehaviour.Popref,
    )
    Isinst = OpCode(
        "isinst",
        OpCodeValue.Isinst,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref,
    )
    Conv_R_Un = OpCode(
        "conv.r.un",
        OpCodeValue.Conv_R_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr8,
        StackBehaviour.Pop1,
    )
    Unbox = OpCode(
        "unbox",
        OpCodeValue.Unbox,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popref,
    )
    Throw = OpCode(
        "throw",
        OpCodeValue.Throw,
        OperandType.InlineNone,
        FlowControl.Throw,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref,
    )
    Ldfld = OpCode(
        "ldfld",
        OpCodeValue.Ldfld,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push1,
        StackBehaviour.Popref,
    )
    Ldflda = OpCode(
        "ldflda",
        OpCodeValue.Ldflda,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref,
    )
    Stfld = OpCode(
        "stfld",
        OpCodeValue.Stfld,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_pop1,
    )
    Ldsfld = OpCode(
        "ldsfld",
        OpCodeValue.Ldsfld,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldsflda = OpCode(
        "ldsflda",
        OpCodeValue.Ldsflda,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Stsfld = OpCode(
        "stsfld",
        OpCodeValue.Stsfld,
        OperandType.InlineField,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Stobj = OpCode(
        "stobj",
        OpCodeValue.Stobj,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_pop1,
    )
    Conv_Ovf_I1_Un = OpCode(
        "conv.ovf.i1.un",
        OpCodeValue.Conv_Ovf_I1_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I2_Un = OpCode(
        "conv.ovf.i2.un",
        OpCodeValue.Conv_Ovf_I2_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I4_Un = OpCode(
        "conv.ovf.i4.un",
        OpCodeValue.Conv_Ovf_I4_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I8_Un = OpCode(
        "conv.ovf.i8.un",
        OpCodeValue.Conv_Ovf_I8_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U1_Un = OpCode(
        "conv.ovf.u1.un",
        OpCodeValue.Conv_Ovf_U1_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U2_Un = OpCode(
        "conv.ovf.u2.un",
        OpCodeValue.Conv_Ovf_U2_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U4_Un = OpCode(
        "conv.ovf.u4.un",
        OpCodeValue.Conv_Ovf_U4_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U8_Un = OpCode(
        "conv.ovf.u8.un",
        OpCodeValue.Conv_Ovf_U8_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I_Un = OpCode(
        "conv.ovf.i.un",
        OpCodeValue.Conv_Ovf_I_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U_Un = OpCode(
        "conv.ovf.u.un",
        OpCodeValue.Conv_Ovf_U_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Box = OpCode(
        "box",
        OpCodeValue.Box,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushref,
        StackBehaviour.Pop1,
    )
    Newarr = OpCode(
        "newarr",
        OpCodeValue.Newarr,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushref,
        StackBehaviour.Popi,
    )
    Ldlen = OpCode(
        "ldlen",
        OpCodeValue.Ldlen,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref,
    )
    Ldelema = OpCode(
        "ldelema",
        OpCodeValue.Ldelema,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_I1 = OpCode(
        "ldelem.i1",
        OpCodeValue.Ldelem_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_U1 = OpCode(
        "ldelem.u1",
        OpCodeValue.Ldelem_U1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_I2 = OpCode(
        "ldelem.i2",
        OpCodeValue.Ldelem_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_U2 = OpCode(
        "ldelem.u2",
        OpCodeValue.Ldelem_U2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_I4 = OpCode(
        "ldelem.i4",
        OpCodeValue.Ldelem_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_U4 = OpCode(
        "ldelem.u4",
        OpCodeValue.Ldelem_U4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_I8 = OpCode(
        "ldelem.i8",
        OpCodeValue.Ldelem_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi8,
        StackBehaviour.Popref_popi,
    )
    Ldelem_I = OpCode(
        "ldelem.i",
        OpCodeValue.Ldelem_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushi,
        StackBehaviour.Popref_popi,
    )
    Ldelem_R4 = OpCode(
        "ldelem.r4",
        OpCodeValue.Ldelem_R4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushr4,
        StackBehaviour.Popref_popi,
    )
    Ldelem_R8 = OpCode(
        "ldelem.r8",
        OpCodeValue.Ldelem_R8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushr8,
        StackBehaviour.Popref_popi,
    )
    Ldelem_Ref = OpCode(
        "ldelem.ref",
        OpCodeValue.Ldelem_Ref,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Pushref,
        StackBehaviour.Popref_popi,
    )
    Stelem_I = OpCode(
        "stelem.i",
        OpCodeValue.Stelem_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popi,
    )
    Stelem_I1 = OpCode(
        "stelem.i1",
        OpCodeValue.Stelem_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popi,
    )
    Stelem_I2 = OpCode(
        "stelem.i2",
        OpCodeValue.Stelem_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popi,
    )
    Stelem_I4 = OpCode(
        "stelem.i4",
        OpCodeValue.Stelem_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popi,
    )
    Stelem_I8 = OpCode(
        "stelem.i8",
        OpCodeValue.Stelem_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popi8,
    )
    Stelem_R4 = OpCode(
        "stelem.r4",
        OpCodeValue.Stelem_R4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popr4,
    )
    Stelem_R8 = OpCode(
        "stelem.r8",
        OpCodeValue.Stelem_R8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popr8,
    )
    Stelem_Ref = OpCode(
        "stelem.ref",
        OpCodeValue.Stelem_Ref,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_popref,
    )
    Ldelem = OpCode(
        "ldelem",
        OpCodeValue.Ldelem,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push1,
        StackBehaviour.Popref_popi,
    )
    Stelem = OpCode(
        "stelem",
        OpCodeValue.Stelem,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popref_popi_pop1,
    )
    Unbox_Any = OpCode(
        "unbox.any",
        OpCodeValue.Unbox_Any,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push1,
        StackBehaviour.Popref,
    )
    Conv_Ovf_I1 = OpCode(
        "conv.ovf.i1",
        OpCodeValue.Conv_Ovf_I1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U1 = OpCode(
        "conv.ovf.u1",
        OpCodeValue.Conv_Ovf_U1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I2 = OpCode(
        "conv.ovf.i2",
        OpCodeValue.Conv_Ovf_I2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U2 = OpCode(
        "conv.ovf.u2",
        OpCodeValue.Conv_Ovf_U2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I4 = OpCode(
        "conv.ovf.i4",
        OpCodeValue.Conv_Ovf_I4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U4 = OpCode(
        "conv.ovf.u4",
        OpCodeValue.Conv_Ovf_U4,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I8 = OpCode(
        "conv.ovf.i8",
        OpCodeValue.Conv_Ovf_I8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U8 = OpCode(
        "conv.ovf.u8",
        OpCodeValue.Conv_Ovf_U8,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi8,
        StackBehaviour.Pop1,
    )
    Refanyval = OpCode(
        "refanyval",
        OpCodeValue.Refanyval,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Ckfinite = OpCode(
        "ckfinite",
        OpCodeValue.Ckfinite,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushr8,
        StackBehaviour.Pop1,
    )
    Mkrefany = OpCode(
        "mkrefany",
        OpCodeValue.Mkrefany,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Popi,
    )
    Ldtoken = OpCode(
        "ldtoken",
        OpCodeValue.Ldtoken,
        OperandType.InlineTok,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Conv_U2 = OpCode(
        "conv.u2",
        OpCodeValue.Conv_U2,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_U1 = OpCode(
        "conv.u1",
        OpCodeValue.Conv_U1,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_I = OpCode(
        "conv.i",
        OpCodeValue.Conv_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_I = OpCode(
        "conv.ovf.i",
        OpCodeValue.Conv_Ovf_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Conv_Ovf_U = OpCode(
        "conv.ovf.u",
        OpCodeValue.Conv_Ovf_U,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Add_Ovf = OpCode(
        "add.ovf",
        OpCodeValue.Add_Ovf,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Add_Ovf_Un = OpCode(
        "add.ovf.un",
        OpCodeValue.Add_Ovf_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Mul_Ovf = OpCode(
        "mul.ovf",
        OpCodeValue.Mul_Ovf,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Mul_Ovf_Un = OpCode(
        "mul.ovf.un",
        OpCodeValue.Mul_Ovf_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Sub_Ovf = OpCode(
        "sub.ovf",
        OpCodeValue.Sub_Ovf,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Sub_Ovf_Un = OpCode(
        "sub.ovf.un",
        OpCodeValue.Sub_Ovf_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop1_pop1,
    )
    Endfinally = OpCode(
        "endfinally",
        OpCodeValue.Endfinally,
        OperandType.InlineNone,
        FlowControl.Return,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.PopAll,
    )
    Leave = OpCode(
        "leave",
        OpCodeValue.Leave,
        OperandType.InlineBrTarget,
        FlowControl.Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.PopAll,
    )
    Leave_S = OpCode(
        "leave.s",
        OpCodeValue.Leave_S,
        OperandType.ShortInlineBrTarget,
        FlowControl.Branch,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.PopAll,
    )
    Stind_I = OpCode(
        "stind.i",
        OpCodeValue.Stind_I,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi,
    )
    Conv_U = OpCode(
        "conv.u",
        OpCodeValue.Conv_U,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Prefix7 = OpCode(
        "prefix7",
        OpCodeValue.Prefix7,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix6 = OpCode(
        "prefix6",
        OpCodeValue.Prefix6,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix5 = OpCode(
        "prefix5",
        OpCodeValue.Prefix5,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix4 = OpCode(
        "prefix4",
        OpCodeValue.Prefix4,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix3 = OpCode(
        "prefix3",
        OpCodeValue.Prefix3,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix2 = OpCode(
        "prefix2",
        OpCodeValue.Prefix2,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefix1 = OpCode(
        "prefix1",
        OpCodeValue.Prefix1,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Prefixref = OpCode(
        "prefixref",
        OpCodeValue.Prefixref,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Nternal,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Arglist = OpCode(
        "arglist",
        OpCodeValue.Arglist,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ceq = OpCode(
        "ceq",
        OpCodeValue.Ceq,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1_pop1,
    )
    Cgt = OpCode(
        "cgt",
        OpCodeValue.Cgt,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1_pop1,
    )
    Cgt_Un = OpCode(
        "cgt.un",
        OpCodeValue.Cgt_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1_pop1,
    )
    Clt = OpCode(
        "clt",
        OpCodeValue.Clt,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1_pop1,
    )
    Clt_Un = OpCode(
        "clt.un",
        OpCodeValue.Clt_Un,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1_pop1,
    )
    Ldftn = OpCode(
        "ldftn",
        OpCodeValue.Ldftn,
        OperandType.InlineMethod,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Ldvirtftn = OpCode(
        "ldvirtftn",
        OpCodeValue.Ldvirtftn,
        OperandType.InlineMethod,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popref,
    )
    Ldarg = OpCode(
        "ldarg",
        OpCodeValue.Ldarg,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldarga = OpCode(
        "ldarga",
        OpCodeValue.Ldarga,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Starg = OpCode(
        "starg",
        OpCodeValue.Starg,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Ldloc = OpCode(
        "ldloc",
        OpCodeValue.Ldloc,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push1,
        StackBehaviour.Pop0,
    )
    Ldloca = OpCode(
        "ldloca",
        OpCodeValue.Ldloca,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Stloc = OpCode(
        "stloc",
        OpCodeValue.Stloc,
        OperandType.InlineVar,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Pop1,
    )
    Localloc = OpCode(
        "localloc",
        OpCodeValue.Localloc,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Popi,
    )
    Endfilter = OpCode(
        "endfilter",
        OpCodeValue.Endfilter,
        OperandType.InlineNone,
        FlowControl.Return,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Unaligned = OpCode(
        "unaligned.",
        OpCodeValue.Unaligned,
        OperandType.ShortInlineI,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Volatile = OpCode(
        "volatile.",
        OpCodeValue.Volatile,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Tailcall = OpCode(
        "tail.",
        OpCodeValue.Tailcall,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Initobj = OpCode(
        "initobj",
        OpCodeValue.Initobj,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Popi,
    )
    Constrained = OpCode(
        "constrained.",
        OpCodeValue.Constrained,
        OperandType.InlineType,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Cpblk = OpCode(
        "cpblk",
        OpCodeValue.Cpblk,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi_popi,
    )
    Initblk = OpCode(
        "initblk",
        OpCodeValue.Initblk,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Push0,
        StackBehaviour.Popi_popi_popi,
    )
    No = OpCode(
        "no.",
        OpCodeValue.No,
        OperandType.ShortInlineI,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Rethrow = OpCode(
        "rethrow",
        OpCodeValue.Rethrow,
        OperandType.InlineNone,
        FlowControl.Throw,
        OpCodeType.Objmodel,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )
    Sizeof = OpCode(
        "sizeof",
        OpCodeValue.Sizeof,
        OperandType.InlineType,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop0,
    )
    Refanytype = OpCode(
        "refanytype",
        OpCodeValue.Refanytype,
        OperandType.InlineNone,
        FlowControl.Next,
        OpCodeType.Primitive,
        StackBehaviour.Pushi,
        StackBehaviour.Pop1,
    )
    Readonly = OpCode(
        "readonly.",
        OpCodeValue.Readonly,
        OperandType.InlineNone,
        FlowControl.Meta,
        OpCodeType.Prefix,
        StackBehaviour.Push0,
        StackBehaviour.Pop0,
    )

    def __init__(self):
        # group opcodes by size; used to parse instructions later
        self.one_byte_op_codes: List[OpCode] = [OpCodes.UNKNOWN1] * 0x100
        self.two_byte_op_codes: List[OpCode] = [OpCodes.UNKNOWN2] * 0x100

        for (_, opcode) in inspect.getmembers(OpCodes, lambda o: isinstance(o, OpCode)):
            if opcode.value >> 8 == 0:
                self.one_byte_op_codes[opcode.value] = opcode
            elif opcode.value >> 8 == 0xFE:
                self.two_byte_op_codes[opcode.value & 0xFF] = opcode
