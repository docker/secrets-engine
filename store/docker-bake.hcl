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
