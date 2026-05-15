# Lattice — Arch Linux packaging

This directory ships an Arch-native `PKGBUILD` for Lattice. It is a
**split package** that produces two pacman packages from one source
tree:

| Package | Contents |
|---|---|
| `lattice-desktop` | Tauri 2 chat client + icons + `.desktop` entry |
| `lattice-server`  | Home-server daemon + systemd unit + sysusers/tmpfiles drop-ins |

Source is pulled by commit hash from `github.com/suhteevah/lattice`.
Bump `_commit` (and reset `pkgrel` to 1) when packaging a new revision.

---

## Quick install

Pre-flight — the AUR / extra packages you need on PATH before
`makepkg` runs:

```bash
# Extra (official):
sudo pacman -S rust pkgconf capnproto wasm-bindgen git \
               webkit2gtk-4.1 libsoup3 gtk3 librsvg \
               libayatana-appindicator

# AUR (need an AUR helper, e.g. paru or yay):
paru -S trunk
# or, if you don't want the AUR helper:
cargo install trunk --locked
```

Then build + install both packages:

```bash
cd packaging/arch
makepkg -si
```

`-s` resolves makedepends, `-i` installs the resulting packages.

Install only one:

```bash
makepkg
sudo pacman -U lattice-desktop-*.pkg.tar.zst
# or
sudo pacman -U lattice-server-*.pkg.tar.zst
```

---

## After install

### Desktop client

Launch from your DE app menu (`Lattice`) or:

```bash
lattice-desktop
```

First run bootstraps a fresh identity. Configure the home-server URL
via the ⚙ button in the chat-shell sidebar. Default points at
`http://127.0.0.1:8080`.

### Home server

`/etc/lattice/lattice.toml` is the config file (marked `backup=` in
the PKGBUILD — pacman won't overwrite your local edits on upgrade).
Environment variables override TOML; see
[`docs/usage/self-hosting.md`](../../docs/usage/self-hosting.md) for
the full set.

Bring it up:

```bash
sudo systemctl enable --now lattice-server
sudo journalctl -u lattice-server -f
```

The unit binds to `0.0.0.0:8444` by default. If you want a different
port, drop a systemd override:

```bash
sudo systemctl edit lattice-server
# add:
[Service]
Environment=LATTICE__SERVER__BIND_ADDR=0.0.0.0:9443
```

Federation key lands at `/var/lib/lattice/federation.key` on first
start. **Back it up** — if you lose it every peer that has
TOFU-pinned this server breaks until they re-pin.

---

## Build notes / caveats

### `trunk` is in the AUR

`PKGBUILD` lists `trunk` in `makedepends` for completeness, but
`makepkg -s` won't auto-install it from the AUR. Install it first
via your AUR helper, or via `cargo install trunk --locked`.

### `RUSTC_WRAPPER=sccache` will hang

If your shell exports `RUSTC_WRAPPER=sccache` globally, the lattice
build will time out waiting for the sccache daemon. Unset before
`makepkg`:

```bash
RUSTC_WRAPPER= makepkg -si
```

This was the same trip-up we hit on cnc-server.

### `capnp` is mandatory

`lattice-protocol/build.rs` shells out to the Cap'n Proto compiler.
If you see `Failed to execute capnp --version`, the `capnproto`
package isn't installed (or `capnp` isn't on PATH for the build
shell). The `makedepends=(... capnproto ...)` line covers this on
Arch.

### `libappindicator-gtk3` vs `libayatana-appindicator`

This `PKGBUILD` uses `libayatana-appindicator` (the modern Arch
package). If you're on an older Arch derivative that still has
`libappindicator-gtk3`, swap the names in both the `makedepends`
and the `depends` of `package_lattice-desktop`.

### No `.AppImage` from this packaging path

`cargo tauri build` would also emit `.deb` + `.AppImage` artifacts,
but we intentionally call `cargo build -p lattice-desktop` directly
to skip the bundlers — pacman only needs the binary + the desktop
hint files. Saves ~5 min on the build, and dodges the
`appimagetool` GitHub-rate-limit hang we hit on cnc-server.

If you specifically want an `.AppImage` from this tree, swap step 3
of `build()` for:

```bash
cd apps/lattice-desktop/src-tauri
cargo tauri build -c '{"build":{"beforeBuildCommand":""}}' --bundles appimage
```

The output lands at
`target/release/bundle/appimage/Lattice_0.1.0_amd64.AppImage`.

---

## Bumping the package

When upstream lands new commits worth packaging:

1. Update `_commit` to the new full SHA.
2. Reset `pkgrel=1` (we're tracking by commit, so every new `_commit`
   is a new "version" downstream).
3. Run `makepkg --printsrcinfo > .SRCINFO` if you're publishing
   to the AUR.

`pkgver()` auto-derives a string like `0.1.0.r5.74817ba` from the
checkout, so `pkgver=` in the file is the floor; the function
overrides at build time.

---

## File layout

```
packaging/arch/
├── PKGBUILD            # the recipe (this is what pacman + makepkg read)
├── README.md           # this file
└── .SRCINFO            # generated for AUR publish; not checked in by default
```

To publish to the AUR (when ready):

```bash
makepkg --printsrcinfo > .SRCINFO
git init aur-repo && cd aur-repo
git remote add origin ssh://aur@aur.archlinux.org/lattice.git
cp ../PKGBUILD ../README.md ../.SRCINFO .
git add . && git commit -m 'lattice 0.1.0.r0.74817ba-1'
git push -u origin master
```
