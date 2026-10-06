Removes one or more named secrets from the local OS keychain. Use `--all` to
remove every stored secret at once.

The secrets engine must authorize the removal first and may prompt you. Denied
access removes nothing and fails with "access denied".
