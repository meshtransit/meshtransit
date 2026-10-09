# Linux service readiness rc2 sample 1

These redacted reports cover five coordinated `meshnetd`/`meshd` restarts on
each dedicated amd64 qualification host. Every iteration made exactly one local
health request immediately after `systemctl restart` returned.

- `ubuntu-26.json`: Ubuntu 26.04, kernel 7.0.0-31-generic.
- `debian-13.json`: Debian 13, kernel 6.12.107+deb13-amd64.

Both reports are bound to package `0.1.0~rc2+03c417d`, commit
`03c417de00a600ceddc7ad620509182abe4902b9`, and package SHA-256
`d8a0ff209041d4a07bbab76adc89e72c37a5f6da7d4b496f2a424408f884a22f`.
They contain no host address, hostname, process ID, profile identifier, control
endpoint, key fingerprint, credential, or local socket path.
