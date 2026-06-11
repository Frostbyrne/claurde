# AUR packaging for clAURde

This directory holds the `PKGBUILD` and `.SRCINFO` for the AUR `claurde` package.
The AUR package lives in its **own** git repo (`ssh://aur@aur.archlinux.org/claurde.git`),
separate from the source repo — these files are kept here for reference and review.

## Publishing / updating the AUR package

1. Cut the matching GitHub release first (tag `v<pkgver>`), so the source
   tarball URL resolves.
2. Pin the checksum:
   ```sh
   updpkgsums          # replaces sha256sums=('SKIP') with the real digest
   makepkg --printsrcinfo > .SRCINFO
   ```
3. Build-test in a clean chroot:
   ```sh
   makepkg -f          # or: extra-x86_64-build
   namcap PKGBUILD claurde-*.pkg.tar.zst
   ```
4. Push to the AUR (requires your AUR account SSH key):
   ```sh
   git clone ssh://aur@aur.archlinux.org/claurde.git aur-claurde
   cp PKGBUILD .SRCINFO aur-claurde/
   cd aur-claurde
   git add PKGBUILD .SRCINFO
   git commit -m "upgpkg: claurde 1.0.0-1"
   git push
   ```
