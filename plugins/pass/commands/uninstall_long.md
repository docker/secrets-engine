Deletes the named plugins from the engine's plugin directory.

NAME is a plugin's file name in that directory: the name that
`docker pass install` printed, or the one set with `--name`.

If the plugin directory is not writable, the deletion runs through `sudo`.

A deleted plugin keeps running until the engine restarts, so restart it
afterwards.
