# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os

import setuptools

requirements = []

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("dncil", "version.py"), "r") as f:
    exec(f.read())


# via: https://packaging.python.org/guides/making-a-pypi-friendly-readme/
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), "r") as f:
    long_description = f.read()


setuptools.setup(
    name="dncil",
    version=__version__,
    description="The FLARE team's open-source library to disassemble Common Intermediate Language (CIL) instructions.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Mike Hunhoff",
    author_email="michael.hunhoff@mandiant.com",
    url="https://www.github.com/mandiant/dncil",
    packages=setuptools.find_packages(exclude=["tests", "scripts"]),
    package_dir={"dncil": "dncil"},
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest==7.1.1",
            "pytest-sugar==0.9.4",
            "pytest-instafail==0.4.2",
            "pytest-cov==3.0.0",
            "pycodestyle==2.8.0",
            "black==22.3.0",
            "isort==5.10.1",
            "mypy==0.942",
            "dnfile==0.10.0",
            "hexdump==3.3.0",
        ],
    },
    zip_safe=False,
    keywords=".net dotnet cil il disassembly FLARE",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
