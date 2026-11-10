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

**Subnet routes:** with **Use subnet routes** on, the phone reaches the Sites
its rules grant: the library puts each granted private prefix on the VPN
interface (public ones need a second switch), refusing one that overlaps a
network the phone is attached to or holds its DNS server or gateway. The setting is off until the person turns
it on, is kept in the app's private storage, and applies within 10 seconds.
The connection screen shows the router each Site goes through. Changing the
routes makes a new VPN interface, as Android cannot change one in place.

**Exit node:** the **Exit node** card takes an Exit Pool's name (or `auto`)
the rules grant. While one is chosen the VPN interface carries `0.0.0.0/0`
and `::/0` (less the phone's own private network with **Keep this phone's
own network reachable**, as routes around it, so no Android 13 API is
needed) and the exit node's DNS forwarder as its only DNS server; while no
exit node answers, a resolver inside the mesh that answers nothing, never
the network's. The card shows the exit node used, or why traffic is
blocked, and an **Approve** button for exit nodes added since the pool was
first used. For a kill switch while MeshTransit itself is off, turn on
**Always-on VPN** and **Block connections without VPN** in Android's VPN
settings; the app cannot. Without an exit node the VPN carries only mesh
traffic, so blocking connections without it leaves the phone without
Internet.

**Captive portals:** Android checks each Wi-Fi outside the VPN and shows its
own **Sign in to Wi-Fi network** notification; its sign-in page reaches the
portal over the Wi-Fi directly, also while an exit node is chosen and with
**Block connections without VPN** on, while every other app stays behind the
VPN. No window is needed on Android: sign in from that notification and the
exit node carries the traffic again once the Wi-Fi lets it through. Tried on
Android 12 (MIUI) on 2026-10-21 with a simulated portal.

**Accounts (device logout design §7):** the core keeps one profile per account. `ProfilesJSON` lists them as
`{"version":1,"profiles":[{"id","name","controlUrl","active","state"}]}`, `state` being `registered`, `signed_out`,
`authorization_required`, `unregistered`, `untrusted` or `unreadable`. `AddAccount` adds a profile for the active
profile's server with the same pinned key, then makes it active, so the next browser sign-in makes another Device;
the previous account keeps its Device and `ActivateProfile` switches back. `SignOut` keeps the Device (`signed_out`;
`removed` when Core removed an ephemeral one instead; `unsupported` on an older server; `not_permitted` for a
Workspace Device; `none`); a signed-out Device signs back in with the browser only, never with an enrollment key.
`Logout` removes the Device. `RemoveProfile(id, local)` removes an account not in use, its Device through Core first
with that account's own keys (`removed`, `already_removed`, `none`, `pending`, `left` with `local`; `refused` when
Core refuses the keys, then only `local` is left; `active`, `busy`, `incomplete`); it can take up to a minute.

Not yet: MeshTransit DNS for mesh names (the VPN sets a DNS server only for an exit node), Device aliases, port
mapping. Logs are in `logcat` under the
tags `MeshCore`, `MeshVpnService` and `VpnController`; release builds log
warnings and errors only.

Uninstalling the app or clearing its data leaves the Device registered: use
**Remove this device** first, or revoke it in the Console.

## iOS

There is no iOS app yet. `make mobile-ios` builds `bin/mobile/MeshCore.xcframework`
(class prefix `MT`) for a future app using a packet tunnel extension.
