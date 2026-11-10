# sinty-parentald

Keeps the parental controls of each account in
`/var/lib/singularity/parental/USER.conf`, the file the Singularity session
reads to block apps, enforce bedtime and filter the web. It starts on demand
through D-Bus activation.

## Who may change a policy

Root, or an administrator (a member of `wheel`, `sudo` or `admin`, or an
account whose primary group is one of them) changing someone else's policy.
An account can never change or clear its own limits. Policies are only kept
for regular accounts, uid 1000 and up.

## D-Bus

Name `dev.sinty.Parental1`, object `/dev/sinty/Parental1`, interface
`dev.sinty.Parental1`.

| Member | Signature | |
| --- | --- | --- |
| `SetPolicy` | `(s user, s policy)` | a key file with only `[Apps]`, `[Time]` and `[Web]`, at most 64 KiB |
| `ClearPolicy` | `(s user)` | removing a missing policy succeeds |
| `Changed` | signal `(s user)` | |

A refused caller gets `org.freedesktop.DBus.Error.AccessDenied`; a bad user
or policy `dev.sinty.Parental1.Error.Invalid`.

## Usage

    sinty-parentald [-dir /var/lib/singularity/parental]

## Build

    make build
    make static           # stripped static binary for the image
    make test

Requires Go >= 1.25. The non-stdlib dependency is `github.com/godbus/dbus/v5`.
