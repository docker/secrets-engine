# Engine

The two main tasks of the engine are:
- It implements the resolver interface.
- It's extendable via plugins

# Features

- [x] plugins are started/stopped in parallel to minimize startup/shutdown time
- [x] cross-platform support for
  - [x] Linux
  - [x] Mac
  - [x] Windows
- [ ] plugin runtime that supports
  - [x] engine launched plugins (binaries are located in a plugin folder)
  - [ ] externally launched plugins (binaries connect to the engine socket from the outside)
  - [ ] internal plugins (plugins are shipped as part of the engine binary)
- [ ] configuration
  - [ ] retry behaviour when plugins crash
  - [ ] logging
  - [ ] permanently disable engine launched plugins
  - [ ] permanently disable externally launched plugins