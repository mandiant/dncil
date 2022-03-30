# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from pathlib import Path

CD = Path(__file__).parent
DATA = CD / "data"


def get_data_path_by_name(name):
    if name == "hello-world.exe":
        return DATA / "hello-world" / "hello-world.exe"

    raise ValueError("unknown test file")
