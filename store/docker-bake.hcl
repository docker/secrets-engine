// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

group "default" {
  targets = [
    "fedora_43_gnome_keyring",
    # disabling kdewallet tests for now, it doesn't work in headless mode
    # it just prompts anyway...
    # "fedora_43_kdewallet",
    # "ubuntu_24_kdewallet",
    "ubuntu_24_gnome_keyring"
  ]
}

variable "GO_VERSION" {
  default = "1.24"
}

target "fedora_43_gnome_keyring" {
  dockerfile = "store/Dockerfile"
  target     = "fedora-43-gnome-keyring"
  context    = "."
  args       = {
    GO_VERSION = GO_VERSION
  }
}

target "fedora_43_kdewallet" {
  dockerfile = "store/Dockerfile"
  target     = "fedora-43-kdewallet"
  context    = "."
  args       = {
    GO_VERSION = GO_VERSION
  }
}

target "ubuntu_24_kdewallet" {
  dockerfile = "store/Dockerfile"
  target     = "ubuntu-24-kdewallet"
  context    = "."
  args       = {
    GO_VERSION = GO_VERSION
  }
}

target "ubuntu_24_gnome_keyring" {
  dockerfile = "store/Dockerfile"
  target     = "ubuntu-24-gnome-keyring"
  context    = "."
  args       = {
    GO_VERSION = GO_VERSION
  }
}
