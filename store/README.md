# Store

The `store` module is a strict interface for storing credentials and secrets.
It is tightly coupled to the secrets engine and requires a valid `secrets.ID`.

Supported stores include:

- Linux keychain (gnome-keyring and kdewallet)
- macOS keychain
