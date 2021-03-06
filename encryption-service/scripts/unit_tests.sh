#!/bin/bash

# Copyright 2020 CYBERCRYPT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run all unit tests. Usage:
#   ./scripts/unit_tests.sh

set -euo pipefail

source ./scripts/build-env
source ./scripts/dev-env

export TEST_FOLDERS=$(go list ./... | grep -vE 'encryption-service$|e2e_tests')
echo '[*] testfolders: '
echo $TEST_FOLDERS
echo '[*] running unit tests'
go test -count=1 -v $TEST_FOLDERS
