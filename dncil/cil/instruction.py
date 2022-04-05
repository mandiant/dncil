# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Union, Optional, cast

from dncil.cil.enums import OpCodeValue, OperandType

if TYPE_CHECKING:
    from dncil.clr.local import Local
    from dncil.clr.token import Token
    from dncil.cil.opcode import OpCode
    from dncil.clr.argument import Argument


class Instruction:
    """store managed instruction"""

    def __init__(self):
        self.offset: int
        self.opcode: OpCode
        self.opcode_bytes: bytes
        self.operand: Union[Token, Local, Argument, list, int, float, None]
        self.operand_bytes: bytes

    def __str__(self) -> str:
        return (
            "{:04X}".format(self.offset)
            + "    "
            + f"{' '.join('{:02x}'.format(b) for b in self.get_bytes()) : <20}"
            + f"{str(self.opcode) : <15}"
            + (str(self.operand) if self.operand is not None else "")
        )

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.offset

    @property
    def mnemonic(self):
        """get instruction opcode mnemonic"""
        return self.opcode.name

    @property
    def size(self) -> int:
        """get instruction size"""
        opcode: OpCode = self.opcode

        if opcode.operand_type in (
            OperandType.InlineBrTarget,
            OperandType.InlineField,
            OperandType.InlineI,
            OperandType.InlineMethod,
            OperandType.InlineSig,
            OperandType.InlineString,
            OperandType.InlineTok,
            OperandType.InlineType,
            OperandType.ShortInlineR,
        ):
            return opcode.size + 4

        elif opcode.operand_type in (OperandType.InlineI8, OperandType.InlineR):
            return opcode.size + 8
        elif opcode.operand_type in (OperandType.InlineSwitch,):
            targets = cast(list, self.operand)
            return opcode.size + 4 + (len(targets) * 4 if targets else 0)
        elif opcode.operand_type in (OperandType.InlineVar,):
            return opcode.size + 2
        elif opcode.operand_type in (
            OperandType.ShortInlineBrTarget,
            OperandType.ShortInlineI,
            OperandType.ShortInlineVar,
        ):
            return opcode.size + 1
        elif opcode.operand_type in (OperandType.InlineNone, OperandType.InlinePhi):
            return opcode.size
        else:
            return opcode.size

    def get_mnemonic(self) -> str:
        """get instruction mnemonic"""
        return self.mnemonic

    def get_size(self) -> int:
        """get instruction size"""
        return self.size

    def get_opcode_size(self) -> int:
        """get instruction opcode size"""
        return len(self.opcode_bytes)

    def get_operand_size(self) -> int:
        """get instruction operand size"""
        return len(self.operand_bytes)

    def get_bytes(self) -> bytes:
        """get instruction bytes"""
        return self.opcode_bytes + self.operand_bytes

    def get_opcode_bytes(self) -> bytes:
        """get instruction opcode bytes"""
        return self.opcode_bytes

    def get_operand_bytes(self) -> bytes:
        """get instruction operand bytes"""
        return self.operand_bytes

    def is_leave(self) -> bool:
        """check if instruction is leave"""
        return self.opcode.value in (OpCodeValue.Leave, OpCodeValue.Leave_S)

    def is_br(self) -> bool:
        """check if instruction is generic branch"""
        return self.opcode.value in (OpCodeValue.Br, OpCodeValue.Br_S)

    def is_br_false(self) -> bool:
        """check if instruction is branch false"""
        return self.opcode.value in (OpCodeValue.Brfalse, OpCodeValue.Brfalse_S)

    def is_br_true(self) -> bool:
        """check if instruction is branch true"""
        return self.opcode.value in (OpCodeValue.Brtrue, OpCodeValue.Brtrue_S)

    def is_cond_br(self) -> bool:
        """check if instruction is conditional branch"""
        return self.opcode.value in (
            OpCodeValue.Bge,
            OpCodeValue.Bge_S,
            OpCodeValue.Bge_Un,
            OpCodeValue.Bge_Un_S,
            OpCodeValue.Blt,
            OpCodeValue.Blt_S,
            OpCodeValue.Blt_Un,
            OpCodeValue.Blt_Un_S,
            OpCodeValue.Bgt,
            OpCodeValue.Bgt_S,
            OpCodeValue.Bgt_Un,
            OpCodeValue.Bgt_Un_S,
            OpCodeValue.Ble,
            OpCodeValue.Ble_S,
            OpCodeValue.Ble_Un,
            OpCodeValue.Ble_Un_S,
            OpCodeValue.Brfalse,
            OpCodeValue.Brfalse_S,
            OpCodeValue.Brtrue,
            OpCodeValue.Brtrue_S,
            OpCodeValue.Beq,
            OpCodeValue.Beq_S,
            OpCodeValue.Bne_Un,
            OpCodeValue.Bne_Un_S,
        )

    def is_ldstr(self) -> bool:
        """check if instruction is load string"""
        return self.opcode.value in (OpCodeValue.Ldstr,)

    def is_ldc(self) -> bool:
        """check if instruction is load constant"""
        return self.opcode.value in (
            OpCodeValue.Ldc_I4_M1,
            OpCodeValue.Ldc_I4_0,
            OpCodeValue.Ldc_I4_1,
            OpCodeValue.Ldc_I4_2,
            OpCodeValue.Ldc_I4_3,
            OpCodeValue.Ldc_I4_4,
            OpCodeValue.Ldc_I4_5,
            OpCodeValue.Ldc_I4_6,
            OpCodeValue.Ldc_I4_7,
            OpCodeValue.Ldc_I4_8,
            OpCodeValue.Ldc_I4_S,
            OpCodeValue.Ldc_I4,
            OpCodeValue.Ldc_I8,
            OpCodeValue.Ldc_R4,
            OpCodeValue.Ldc_R8,
        )

    def get_ldc(self) -> Union[int, float, None]:
        """get constant for load instruction"""
        if self.opcode.value == OpCodeValue.Ldc_I4_M1:
            return -1
        elif self.opcode.value == OpCodeValue.Ldc_I4_0:
            return 0
        elif self.opcode.value == OpCodeValue.Ldc_I4_1:
            return 1
        elif self.opcode.value == OpCodeValue.Ldc_I4_2:
            return 2
        elif self.opcode.value == OpCodeValue.Ldc_I4_3:
            return 3
        elif self.opcode.value == OpCodeValue.Ldc_I4_4:
            return 4
        elif self.opcode.value == OpCodeValue.Ldc_I4_5:
            return 5
        elif self.opcode.value == OpCodeValue.Ldc_I4_6:
            return 6
        elif self.opcode.value == OpCodeValue.Ldc_I4_7:
            return 7
        elif self.opcode.value == OpCodeValue.Ldc_I4_8:
            return 8
        elif self.opcode.value == OpCodeValue.Ldc_I4_S:
            return cast(int, self.operand)
        elif self.opcode.value == OpCodeValue.Ldc_I4:
            return cast(int, self.operand)
        elif self.opcode.value == OpCodeValue.Ldc_I8:
            return cast(int, self.operand)
        elif self.opcode.value == OpCodeValue.Ldc_R4:
            return cast(float, self.operand)
        elif self.opcode.value == OpCodeValue.Ldc_R8:
            return cast(float, self.operand)
        else:
            return None

    def is_ldarg(self) -> bool:
        """check if instruction is load argument"""
        return self.opcode.value in (
            OpCodeValue.Ldarg,
            OpCodeValue.Ldarg_0,
            OpCodeValue.Ldarg_1,
            OpCodeValue.Ldarg_2,
            OpCodeValue.Ldarg_3,
            OpCodeValue.Ldarg_S,
            OpCodeValue.Ldarga,
            OpCodeValue.Ldarga_S,
        )

    def get_ldarg(self) -> Optional[Argument]:
        """get argument for load instruction"""
        if self.opcode.value in (OpCodeValue.Ldarg, OpCodeValue.Ldarga, OpCodeValue.Ldarg_S, OpCodeValue.Ldarga_S):
            return cast(Argument, self.operand)
        elif self.opcode.value == OpCodeValue.Ldarg_0:
            return Argument(0)
        elif self.opcode.value == OpCodeValue.Ldarg_1:
            return Argument(1)
        elif self.opcode.value == OpCodeValue.Ldarg_2:
            return Argument(2)
        elif self.opcode.value == OpCodeValue.Ldarg_3:
            return Argument(3)
        else:
            return None

    def is_starg(self) -> bool:
        """check if instruction is store argument"""
        return self.opcode.value in (OpCodeValue.Starg, OpCodeValue.Starg_S)

    def get_starg(self) -> Optional[Argument]:
        """get argument for store instruction"""
        if self.opcode.value in (OpCodeValue.Starg, OpCodeValue.Starg_S):
            return cast(Argument, self.operand)
        else:
            return None

    def is_ldloc(self) -> bool:
        """check if instruction is load local"""
        return self.opcode.value in (
            OpCodeValue.Ldloc,
            OpCodeValue.Ldloc_0,
            OpCodeValue.Ldarg_1,
            OpCodeValue.Ldarg_2,
            OpCodeValue.Ldloc_3,
            OpCodeValue.Ldloc_S,
            OpCodeValue.Ldloca,
            OpCodeValue.Ldloca_S,
        )

    def get_ldoc(self) -> Optional[Local]:
        """get local for load instruction"""
        if self.opcode.value in (OpCodeValue.Ldloc, OpCodeValue.Ldloc_S, OpCodeValue.Ldloca, OpCodeValue.Ldloca_S):
            return cast(Local, self.operand)
        elif self.opcode.value == OpCodeValue.Ldloc_0:
            return Local(0)
        elif self.opcode.value == OpCodeValue.Ldloc_1:
            return Local(1)
        elif self.opcode.value == OpCodeValue.Ldloc_2:
            return Local(2)
        elif self.opcode.value == OpCodeValue.Ldloc_3:
            return Local(3)
        else:
            return None

    def is_stloc(self) -> bool:
        """check if instruction is store local"""
        return self.opcode.value in (
            OpCodeValue.Stloc,
            OpCodeValue.Stloc_0,
            OpCodeValue.Stloc_1,
            OpCodeValue.Stloc_2,
            OpCodeValue.Stloc_3,
            OpCodeValue.Stloc_S,
        )

    def get_stloc(self) -> Optional[Local]:
        """get local for store instruction"""
        if self.opcode.value in (OpCodeValue.Stloc, OpCodeValue.Stloc_S):
            return cast(Local, self.operand)
        elif self.opcode.value == OpCodeValue.Stloc_0:
            return Local(0)
        elif self.opcode.value == OpCodeValue.Stloc_1:
            return Local(1)
        elif self.opcode.value == OpCodeValue.Stloc_2:
            return Local(2)
        elif self.opcode.value == OpCodeValue.Stloc_3:
            return Local(3)
        else:
            return None
