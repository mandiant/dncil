# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from dncil.cil.enums import ExceptionHandlerType

if TYPE_CHECKING:
    from dncil.clr.token import Token


class ExceptionHandler:
    """store managed method exception handler"""

    TINY_SIZE = 12
    FAT_SIZE = 24

    def __init__(self, exception_type: int):
        self.exception_type: int = exception_type

        self.try_start: int = -1
        self.try_end: int = -1
        self.filter_start: int = -1
        self.handler_start: int = -1
        self.handler_end: int = -1
        self.catch_type: Optional[Token] = None

    def is_catch(self) -> bool:
        """check if exception handler is catch"""
        return self.exception_type & 7 == ExceptionHandlerType.Catch

    def is_filter(self) -> bool:
        """check if exception handler is filter"""
        return self.exception_type & ExceptionHandlerType.Filter != 0

    def is_finally(self) -> bool:
        """check if exception handler is finally"""
        return self.exception_type & ExceptionHandlerType.Finally != 0

    def is_fault(self) -> bool:
        """check if exception handler is fault"""
        return self.exception_type & ExceptionHandlerType.Fault != 0
