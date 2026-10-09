# Linux package

The `meshctl` repository builds a separate amd64 or arm64 Debian package. The
package contains only the unprivileged CLI and documentation; it creates no
users, services, state directories, or network configuration. `meshd` owns all
daemon and privileged-helper lifecycle.

```bash
./packaging/linux/build-deb.sh 0.1.0~alpha1 amd64 dist
./packaging/linux/verify-deb.sh dist/meshctl_0.1.0~alpha1_amd64.deb amd64
sudo dpkg -i dist/meshctl_0.1.0~alpha1_amd64.deb
```

The builder runs on Linux, injects the exact Git commit, honors
`SOURCE_DATE_EPOCH`, and writes a sibling SHA-256 checksum file. Operators need
membership in the `meshtransit` group created by the `meshd` package. Group
changes take effect after a new login session.
