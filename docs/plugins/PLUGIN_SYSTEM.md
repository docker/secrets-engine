# The Plugin System

The secrets engine acts as a server that manages plugins.
I.e., plugins register themselves as clients to the server.
Each plugin also is a server that handles resolver requests from the secrets engine.

## Plugin initialization flow

By default, any plugin can be discovered by scanning the plugin directory for
executables and then launched by the secrets engine. In the case where a plugin
is already known to the secrets engine (e.g. docker CLI), it can discover
the plugin via the System Path.

Alternatively, a plugin can make themselves known to an already running secrets
engine by reusing the default socket.

```mermaid
sequenceDiagram
    participant P as Plugin (provider)
    participant E as Secrets Engine (resolver)

    E->>E: Discover plugins (scan plugin directory)
    Note over P,E: Launch discovered plugins
    E->>E: create socket pair
    E->>E: get socket file descriptors
    E->>E: setup launch command and pass in peer file descriptor
    E->>P: launch (exec) plugin with socket file descriptor
    Note over P: Plugin launch
    P->>P: connect (either from WithConnect opt or from peer file descriptor)
    P->>P: setup multiplexing and resolver server
    Note over E: Connect to plugin
    E->>E: setup socket for multiplexing
    E->>E: setup plugin management server (per plugin!)
    Note over P,E: Start plugin
    E->>E: start management server
    P->>E: register plugin to resolver call
    E->>P: configure plugin call
```
