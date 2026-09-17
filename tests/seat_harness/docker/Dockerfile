# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Disposable Linux sshd fixture image for the seat-control harness
# (docs/SEAT_CONTROL_SPEC.md Revision 5, section 8).
#
# Built FROM debian:12 (public Docker Hub base, pullable in CI). The only
# network steps are the base pull and the single
# `apt-get install openssh-server python3` — the two packages the minbase
# image lacks; every other step is offline and cached. Debian 12 minbase
# already ships the full Template C prerequisite set: dash (/bin/sh),
# coreutils (stat -c, sha256sum, sleep, tail -c, timeout, nohup) and
# util-linux (flock, setsid).
#
# The fixture user's login shell is /usr/local/bin/fixture-shell, a tiny
# exec wrapper that re-execs the real shell with the fixture shim directory
# prepended to PATH. This injects the fixture systemctl/loginctl shims on
# PATH exactly as section 8 requires, without touching /etc/environment or
# PAM.
#
# sshd is started by the harness with -D -e; no ENTRYPOINT, so the harness
# owns the full container lifecycle (create/start/exec/stop/rm).

FROM debian:12

# openssh-server is the sshd fixture itself; python3 is required by the
# fixture servers, the shims, and the upload helpers. Caches purged in-layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server python3 \
    && rm -rf /var/lib/apt/lists/*

# The harness's fixture servers are launched as
# `/usr/local/bin/python3 <script>` so /proc/<pid>/cmdline matches
# launch_argv byte-exactly (a shebang wrapper would replace argv[0] — R-3).
# Debian 12 ships /usr/bin/python3; expose it at the harness's pinned path.
RUN ln -s /usr/bin/python3 /usr/local/bin/python3

# Login shell wrapper first, so useradd sees an executable shell.
RUN mkdir -p /opt/testudo-fixture/bin
COPY fixture-shell /usr/local/bin/fixture-shell
# Guard script used by the L2 two-controller contention tests. It holds the
# fixture guard lock in the background for a bounded time.
COPY hold_guard.sh /opt/testudo-fixture/bin/hold_guard.sh

# Single static layer; no network access at build time.
RUN set -eu; \
    chmod 755 /usr/local/bin/fixture-shell /opt/testudo-fixture/bin/hold_guard.sh; \
    groupadd --gid 22000 fixture; \
    useradd --uid 22000 --gid 22000 --create-home \
      --home-dir /home/fixture --shell /usr/local/bin/fixture-shell fixture; \
    mkdir -p /var/run/sshd /home/fixture/.ssh; \
    printf 'fixture:%s\n' "$(head -c 32 /dev/urandom | base64 | tr -d '\n')" \
      | chpasswd -e; \
    chmod 700 /home/fixture/.ssh; \
    chown -R fixture:fixture /home/fixture /opt/testudo-fixture
