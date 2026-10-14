# Android and iOS

## Android

The Android app (`net.meshtransit.app`, Android 10 and later, arm64 devices
and x86_64 emulators) lives in its own repository and embeds the client from
this repository as a library built with gomobile: the same daemon as on
desktop, with the app supplying the VPN interface, the key store and network
changes ([Client](../architecture/client.md#mobile)).

### Building the library

```bash
make mobile-tools                     # install gomobile and gobind
make mobile-android ANDROID_API=29    # bin/mobile/meshcore.aar, package net.meshtransit.core
```

The app's `scripts/build-core.sh` runs this target from its `meshcore`
submodule with the app's `minSdk` and copies the `.aar` into the app; it needs
the Android NDK under `ANDROID_HOME`. The library's `APIVersion` is 1; the app
refuses a library with another version.

### Using the app

1. **Control address:** enter the deployment's Control URL.
2. **Trust:** the app shows Core's control key fingerprint; compare it with the
   one your administrator gave you, then trust it. (The app cannot take the
   fingerprint from a link yet, so this check is by eye.)
3. **Register:** sign in with the browser, or use an enrollment key.
4. **Connect:** Android asks for VPN consent the first time. The connection
   screen shows the Network, the Device's addresses and its peers with how many
   are direct or relayed; Disconnect and Log out are there too.

The app protects its own sockets from the VPN, follows network changes, and
uses stable routes so the VPN is not rebuilt for every new peer. Its identity
is encrypted with a key held in the Android Keystore and kept out of backups;
if the Keystore key is lost, the app starts as a new installation.

Not yet: MeshTransit DNS (the VPN sets no DNS server), Device aliases, port
mapping, always-on VPN, more than one profile. Logs are in `logcat` under the
tags `MeshCore`, `MeshVpnService` and `VpnController`; release builds log
warnings and errors only.

Uninstalling the app or clearing its data leaves the Device registered: use
**Log out** first, or revoke it in the Console.

## iOS

There is no iOS app yet. `make mobile-ios` builds `bin/mobile/MeshCore.xcframework`
(class prefix `MT`) for a future app using a packet tunnel extension.
