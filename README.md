<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="cratty-brand/logo/cratty-logo-dark.svg">
    <img src="cratty-brand/logo/cratty-logo-light.svg" alt="cratty" width="360">
  </picture>
</p>

<p align="center">
  A native, GPU-rendered SSH client with an encrypted host vault<br>
  and visual configuration of connection routes and port forwarding.
</p>

---

Cratty is written in Rust and built on [gpui](https://github.com/zed-industries/zed), the UI framework behind the Zed editor. SSH is implemented in-process with [russh](https://github.com/Eugeny/russh): the system `ssh` binary is never invoked, so passwords, keys and prompts behave the same on Windows, macOS and Linux.

The user interface is currently available in Russian only.

## Features

### Connections

- Saved hosts and quick connect by address (`user@host:port`). Hosts from `~/.ssh/config` are not loaded automatically: import them into a chosen vault from its menu (**Import from ~/.ssh/config**), including `ProxyJump`.
- Authentication with SSH agent keys, keys from `~/.ssh`, a specific key file, or a password.
- Host key verification against `~/.ssh/known_hosts`, with confirmation on first connect and a warning when a key changes.

### Routes and port forwarding

- Connection chains through SOCKS5 proxies and intermediate hosts (equivalent to `ssh -J`). The route is shown as a diagram: this computer → hops → server.
- Local (`-L`), remote (`-R`) and dynamic (`-D`, SOCKS) port forwarding. Each rule is drawn as a diagram showing the traffic direction and can be toggled from the session panel without reconnecting.
- SSH agent forwarding with confirmation of every signature.

### Sessions

- Tabs, split terminal panes, and broadcast input to all panes.
- SFTP file manager over the same connection: upload, download, drag and drop, rename, delete.
- Built-in editor for text files on the server.
- Snippets: saved commands for quick input.
- Input prediction on high-latency connections.
- Scrollback search.

### Vault

- Several vaults can exist and be unlocked at the same time. Create and delete them from the sidebar; each vault has its own password, recovery code, lock state and sync folder, and the sidebar groups hosts by vault.
- Hosts, keys, passwords and proxies are stored in an encrypted vault. The key is derived from the master password with Argon2id; records are encrypted with ChaCha20-Poly1305.
- A 24-word BIP39 recovery phrase (English wordlist) in case the master password is lost; 12-word phrases and legacy recovery codes (`XXXX-XXXX-…`) are still accepted.
- Optional passwordless unlock through the OS credential store: Keychain (macOS), Credential Manager (Windows), Secret Service (Linux).
- Automatic lock after inactivity and after the computer resumes from sleep.
- Built-in SSH agent that serves keys from the vault.
- Sync between devices through a shared folder (Dropbox, Syncthing, a network drive). Only encrypted records are written to the folder.

### Interface

- Three areas: sessions and hosts on the left, the terminal in the center, and a session panel on the right with the route, ports and files. Side panels are resizable by dragging their edges.
- Cratty, SynthWave '84, Graphite and Light themes; adjustable terminal background opacity.

## Building

Requires stable Rust with edition 2024 support (1.85 or later).

```sh
git clone https://github.com/auf-gg/cratty.git
cd cratty
cargo run --release
```

The executable is written to `target/release/cratty` (`cratty.exe` on Windows).

**Linux.** gpui needs the following system libraries:

```sh
sudo apt-get install -y build-essential cmake clang libclang-dev pkg-config \
  libfontconfig-dev libfreetype-dev libwayland-dev libxkbcommon-dev \
  libxkbcommon-x11-dev libx11-xcb-dev libxcb1-dev libvulkan1 \
  libasound2-dev libssl-dev libzstd-dev
```

**Windows.** No additional dependencies: cryptography is built on `ring`, so NASM is not required. The application icon is embedded into the executable at build time.

## Usage

```sh
cratty                  # open the window
cratty user@host:2222   # open the window and connect immediately
```

| Environment variable | Purpose |
| --- | --- |
| `CRATTY_PASSWORD` | Password used to connect without a prompt (for automation and tests). |
| `CRATTY_FINGERPRINT` | Expected server key fingerprint, used instead of `known_hosts` verification. |

## Data locations

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Vaults | `%APPDATA%\cratty\vaults.json` (list), `%APPDATA%\cratty\vault` (first), `%APPDATA%\cratty\vaults\<id>` (others) | `$XDG_DATA_HOME/cratty/vaults.json` (list), `…/cratty/vault` (first), `…/cratty/vaults/<id>` (others)<br>(`~/.local/share/cratty/…`) | `~/.local/share/cratty/vaults.json`, `…/vault`, `…/vaults/<id>` |
| Settings | `%APPDATA%\cratty\settings.json` | `$XDG_CONFIG_HOME/cratty/settings.json`<br>(`~/.config/cratty/settings.json`) | `~/.config/cratty/settings.json` |

The exact paths are shown in the app under Settings → General → Data locations («Настройки → Общие → Расположение данных»).

## Project layout

| Directory | Contents |
| --- | --- |
| `src/ssh` | SSH session, authentication, routes, port forwarding, SFTP |
| `src/term` | Terminal emulator, input handling, echo prediction |
| `src/ui` | gpui interface: window, panels, editor, file manager, settings |
| `src/vault_session` | Unlocked vault state and auto-lock |
| `src/agent` | Built-in SSH agent |
| `crates/vault` | Crypto core: key derivation, data key wrapping, record encryption |
| `crates/proto` | Vault record types and serialization |
| `crates/agent` | SSH agent protocol |
| `crates/sync` | Folder-based sync of encrypted records |
| `cratty-brand` | Logos, icons and color palette |

## Tests

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Some integration tests check compatibility with a real OpenSSH server running in a Docker container (`tests/docker`). They are skipped when Docker is not available; set `CRATTY_REQUIRE_DOCKER=1` to make them mandatory.

## License

[MIT](LICENSE).
