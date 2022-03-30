# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import enum


class OpCodeValue(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/Code.cs
    """

    UNKNOWN1 = 0x0100
    UNKNOWN2 = 0x0101
    Add = 0x0058
    Add_Ovf = 0x00D6
    Add_Ovf_Un = 0x00D7
    And = 0x005F
    Arglist = 0xFE00
    Beq = 0x003B
    Beq_S = 0x002E
    Bge = 0x003C
    Bge_S = 0x002F
    Bge_Un = 0x0041
    Bge_Un_S = 0x0034
    Bgt = 0x003D
    Bgt_S = 0x0030
    Bgt_Un = 0x0042
    Bgt_Un_S = 0x0035
    Ble = 0x003E
    Ble_S = 0x0031
    Ble_Un = 0x0043
    Ble_Un_S = 0x0036
    Blt = 0x003F
    Blt_S = 0x0032
    Blt_Un = 0x0044
    Blt_Un_S = 0x0037
    Bne_Un = 0x0040
    Bne_Un_S = 0x0033
    Box = 0x008C
    Br = 0x0038
    Br_S = 0x002B
    Break = 0x0001
    Brfalse = 0x0039
    Brfalse_S = 0x002C
    Brtrue = 0x003A
    Brtrue_S = 0x002D
    Call = 0x0028
    Calli = 0x0029
    Callvirt = 0x006F
    Castclass = 0x0074
    Ceq = 0xFE01
    Cgt = 0xFE02
    Cgt_Un = 0xFE03
    Ckfinite = 0x00C3
    Clt = 0xFE04
    Clt_Un = 0xFE05
    Constrained = 0xFE16
    Conv_I = 0x00D3
    Conv_I1 = 0x0067
    Conv_I2 = 0x0068
    Conv_I4 = 0x0069
    Conv_I8 = 0x006A
    Conv_Ovf_I = 0x00D4
    Conv_Ovf_I_Un = 0x008A
    Conv_Ovf_I1 = 0x00B3
    Conv_Ovf_I1_Un = 0x0082
    Conv_Ovf_I2 = 0x00B5
    Conv_Ovf_I2_Un = 0x0083
    Conv_Ovf_I4 = 0x00B7
    Conv_Ovf_I4_Un = 0x0084
    Conv_Ovf_I8 = 0x00B9
    Conv_Ovf_I8_Un = 0x0085
    Conv_Ovf_U = 0x00D5
    Conv_Ovf_U_Un = 0x008B
    Conv_Ovf_U1 = 0x00B4
    Conv_Ovf_U1_Un = 0x0086
    Conv_Ovf_U2 = 0x00B6
    Conv_Ovf_U2_Un = 0x0087
    Conv_Ovf_U4 = 0x00B8
    Conv_Ovf_U4_Un = 0x0088
    Conv_Ovf_U8 = 0x00BA
    Conv_Ovf_U8_Un = 0x0089
    Conv_R_Un = 0x0076
    Conv_R4 = 0x006B
    Conv_R8 = 0x006C
    Conv_U = 0x00E0
    Conv_U1 = 0x00D2
    Conv_U2 = 0x00D1
    Conv_U4 = 0x006D
    Conv_U8 = 0x006E
    Cpblk = 0xFE17
    Cpobj = 0x0070
    Div = 0x005B
    Div_Un = 0x005C
    Dup = 0x0025
    Endfilter = 0xFE11
    Endfinally = 0x00DC
    Initblk = 0xFE18
    Initobj = 0xFE15
    Isinst = 0x0075
    Jmp = 0x0027
    Ldarg = 0xFE09
    Ldarg_0 = 0x0002
    Ldarg_1 = 0x0003
    Ldarg_2 = 0x0004
    Ldarg_3 = 0x0005
    Ldarg_S = 0x000E
    Ldarga = 0xFE0A
    Ldarga_S = 0x000F
    Ldc_I4 = 0x0020
    Ldc_I4_0 = 0x0016
    Ldc_I4_1 = 0x0017
    Ldc_I4_2 = 0x0018
    Ldc_I4_3 = 0x0019
    Ldc_I4_4 = 0x001A
    Ldc_I4_5 = 0x001B
    Ldc_I4_6 = 0x001C
    Ldc_I4_7 = 0x001D
    Ldc_I4_8 = 0x001E
    Ldc_I4_M1 = 0x0015
    Ldc_I4_S = 0x001F
    Ldc_I8 = 0x0021
    Ldc_R4 = 0x0022
    Ldc_R8 = 0x0023
    Ldelem = 0x00A3
    Ldelem_I = 0x0097
    Ldelem_I1 = 0x0090
    Ldelem_I2 = 0x0092
    Ldelem_I4 = 0x0094
    Ldelem_I8 = 0x0096
    Ldelem_R4 = 0x0098
    Ldelem_R8 = 0x0099
    Ldelem_Ref = 0x009A
    Ldelem_U1 = 0x0091
    Ldelem_U2 = 0x0093
    Ldelem_U4 = 0x0095
    Ldelema = 0x008F
    Ldfld = 0x007B
    Ldflda = 0x007C
    Ldftn = 0xFE06
    Ldind_I = 0x004D
    Ldind_I1 = 0x0046
    Ldind_I2 = 0x0048
    Ldind_I4 = 0x004A
    Ldind_I8 = 0x004C
    Ldind_R4 = 0x004E
    Ldind_R8 = 0x004F
    Ldind_Ref = 0x0050
    Ldind_U1 = 0x0047
    Ldind_U2 = 0x0049
    Ldind_U4 = 0x004B
    Ldlen = 0x008E
    Ldloc = 0xFE0C
    Ldloc_0 = 0x0006
    Ldloc_1 = 0x0007
    Ldloc_2 = 0x0008
    Ldloc_3 = 0x0009
    Ldloc_S = 0x0011
    Ldloca = 0xFE0D
    Ldloca_S = 0x0012
    Ldnull = 0x0014
    Ldobj = 0x0071
    Ldsfld = 0x007E
    Ldsflda = 0x007F
    Ldstr = 0x0072
    Ldtoken = 0x00D0
    Ldvirtftn = 0xFE07
    Leave = 0x00DD
    Leave_S = 0x00DE
    Localloc = 0xFE0F
    Mkrefany = 0x00C6
    Mul = 0x005A
    Mul_Ovf = 0x00D8
    Mul_Ovf_Un = 0x00D9
    Neg = 0x0065
    Newarr = 0x008D
    Newobj = 0x0073
    No = 0xFE19
    Nop = 0x0000
    Not = 0x0066
    Or = 0x0060
    Pop = 0x0026
    Prefix1 = 0x00FE
    Prefix2 = 0x00FD
    Prefix3 = 0x00FC
    Prefix4 = 0x00FB
    Prefix5 = 0x00FA
    Prefix6 = 0x00F9
    Prefix7 = 0x00F8
    Prefixref = 0x00FF
    Readonly = 0xFE1E
    Refanytype = 0xFE1D
    Refanyval = 0x00C2
    Rem = 0x005D
    Rem_Un = 0x005E
    Ret = 0x002A
    Rethrow = 0xFE1A
    Shl = 0x0062
    Shr = 0x0063
    Shr_Un = 0x0064
    Sizeof = 0xFE1C
    Starg = 0xFE0B
    Starg_S = 0x0010
    Stelem = 0x00A4
    Stelem_I = 0x009B
    Stelem_I1 = 0x009C
    Stelem_I2 = 0x009D
    Stelem_I4 = 0x009E
    Stelem_I8 = 0x009F
    Stelem_R4 = 0x00A0
    Stelem_R8 = 0x00A1
    Stelem_Ref = 0x00A2
    Stfld = 0x007D
    Stind_I = 0x00DF
    Stind_I1 = 0x0052
    Stind_I2 = 0x0053
    Stind_I4 = 0x0054
    Stind_I8 = 0x0055
    Stind_R4 = 0x0056
    Stind_R8 = 0x0057
    Stind_Ref = 0x0051
    Stloc = 0xFE0E
    Stloc_0 = 0x000A
    Stloc_1 = 0x000B
    Stloc_2 = 0x000C
    Stloc_3 = 0x000D
    Stloc_S = 0x0013
    Stobj = 0x0081
    Stsfld = 0x0080
    Sub = 0x0059
    Sub_Ovf = 0x00DA
    Sub_Ovf_Un = 0x00DB
    Switch = 0x0045
    Tailcall = 0xFE14
    Throw = 0x007A
    Unaligned = 0xFE12
    Unbox = 0x0079
    Unbox_Any = 0x00A5
    Volatile = 0xFE13
    Xor = 0x0061


class FlowControl(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/FlowControl.cs
    """

    Branch = 0
    Break = 1
    Call = 2
    Cond_Branch = 3
    Meta = 4
    Next = 5
    Phi = 6
    Return = 7
    Throw = 8


class OpCodeType(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/OpCodeType.cs
    """

    Annotation = 0
    Macro = 1
    Nternal = 2
    Objmodel = 3
    Prefix = 4
    Primitive = 5
    Experimental = 6


class StackBehaviour(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/StackBehaviour.cs
    """

    Pop0 = 0
    Pop1 = 1
    Pop1_pop1 = 2
    Popi = 3
    Popi_pop1 = 4
    Popi_popi = 5
    Popi_popi8 = 6
    Popi_popi_popi = 7
    Popi_popr4 = 8
    Popi_popr8 = 9
    Popref = 10
    Popref_pop1 = 11
    Popref_popi = 12
    Popref_popi_popi = 13
    Popref_popi_popi8 = 14
    Popref_popi_popr4 = 15
    Popref_popi_popr8 = 16
    Popref_popi_popref = 17
    Push0 = 18
    Push1 = 19
    Push1_push1 = 20
    Pushi = 21
    Pushi8 = 22
    Pushr4 = 23
    Pushr8 = 24
    Pushref = 25
    Varpop = 26
    Varpush = 27
    Popref_popi_pop1 = 28

    PopAll = 0xFF


class OperandType(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/OperandType.cs
    """

    InlineBrTarget = 0
    InlineField = 1
    InlineI = 2
    InlineI8 = 3
    InlineMethod = 4
    InlineNone = 5
    InlinePhi = 6
    InlineR = 7
    NOT_USED_8 = 8
    InlineSig = 9
    InlineString = 10
    InlineSwitch = 11
    InlineTok = 12
    InlineType = 13
    InlineVar = 14
    ShortInlineBrTarget = 15
    ShortInlineI = 16
    ShortInlineR = 17
    ShortInlineVar = 18


class ExceptionHandlerType(enum.IntEnum):
    """
    https://github.com/0xd4d/dnlib/blob/master/src/DotNet/Emit/ExceptionHandlerType.cs
    """

    Catch = 0
    Filter = 1
    Finally = 2
    Fault = 4
    Duplicated = 8


class CorILMethod(enum.IntEnum):
    SmallFormat = 0
    TinyFormat = 2  # used if code size is even
    FatFormat = 3
    TinyFormat1 = 6  # used if code size is odd
    FormatMask = (1 << 3) - 1
    MoreSects = 8
    InitLocals = 16
    CompressedIL = 0x40


class CorILMethodSect(enum.IntEnum):
    EHTable = 1
    OptILTable = 2
    KindMask = 0x3F
    FatFormat = 0x40
    MoreSects = 0x80
