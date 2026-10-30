# PLUGIN.NMOS delivery

← [Publishing](INDEX.md) · [Repo README](../../README.md)

## Built

No Dockerfile here. `apk-nmos` is compiled into the shared plugin image `apk-plugins:local` from the
`DISCOVERY.Engine/SRC` workspace:

```sh
docker build -f PODS/POD.THICK/DISCOVERY.Engine/Docker/Dockerfile --target plugins -t apk-plugins:local .
```

The same build links `apkaudio_nmos::unicast` into `apk-nmos-control` (PLUGIN.NMOS_CONTROL depends on
this crate by path).

## Tested

By hand: `cargo test -p apkaudio-nmos` (27 tests; the unicast ones use a loopback DNS socket). The
runner answers `outgoing/selftest_run` for module `nmos`. The AMWA suite
(`PODS/POD.protocols/PROTOCOL.discovery.NMOS`) grades the controller, not this agent.

## Shipped

`Docker/docker-compose.yml` extends `plugin-host` (host networking — mDNS does not cross a bridge)
and is `include:`d into compose project `apk-audio`; `Plugin-NMOS` starts on nodes whose roles
include `discovery`. DockTor's `PODS/POD.manager/MANAGER.Docktor/K8/up-stack.sh` rebuilds one stack.
Rows land on the broker; `SRC/gui/` panels are served by the web UI. No live URL of its own.

## Not automated

* No CI builds or tests it.
* No registry: the image is built on each node.
