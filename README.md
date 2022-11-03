# Blackhole

[![Tests](https://github.com/Pyxxil/Blackhole/actions/workflows/test-pr.yml/badge.svg)](https://github.com/Pyxxil/Blackhole/actions/workflows/test-pr.yml)
![Release](https://img.shields.io/github/v/release/pyxxil/blackhole?sort=semver)
![License](https://img.shields.io/github/license/pyxxil/blackhole)
![Docker](https://ghcr-badge.herokuapp.com/pyxxil/blackhole/latest_tag?label=latest)
![Docker](https://ghcr-badge.herokuapp.com/pyxxil/blackhole/size)
[![codecov](https://codecov.io/gh/Pyxxil/Blackhole/branch/main/graph/badge.svg?token=98FLSLAD6M)](https://codecov.io/gh/Pyxxil/Blackhole)

- [Blackhole](#blackhole)
  - [Similar Projects](#similar-projects)
    - [Why Blackhole](#why-blackhole)
  - [Roadmap](#roadmap)

Blackhole is a DNS filtering server. It acts as your DNS server, and will filter out requests that match criteria that the user specifies.

## Similar Projects

The most popular alternatives are:

- [pi-hole](https://github.com/pi-hole/pi-hole)
- [Adguard Home](https://github.com/AdguardTeam/AdGuardHome)
- [NextDNS](https://nextdns.io/)

### Why Blackhole

The above all have something that the others do not (or, if it does exist, it requires some very manual tuning).

## Roadmap

- [ ] Client
  - [ ] View all blocklists
  - [ ] Check that blocklist domain isn't blocked
  - [ ] Check what list(s) blocked a domain
  - [ ] Ability to check overlap of blocklists
- [ ] Server
  - [ ] Prometheus Export
  - [ ] Open Telemetry
  - [ ] Health Endpoint
