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
- [x] plugin runtime that supports
  - [x] engine launched plugins (binaries are located in a plugin folder)
  - [x] externally launched plugins (binaries connect to the engine socket from the outside)
  - [x] internal plugins (plugins are shipped as part of the engine binary)
- [ ] plugin validation logic on registration
  - [x] names must be unique
  - [ ] no conflicting patterns
- [ ] configuration
  - [ ] retry behaviour when plugins crash
  - [ ] logging
  - [ ] permanently disable engine launched plugins
  - [x] permanently disable externally launched plugins