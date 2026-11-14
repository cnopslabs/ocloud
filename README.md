# OCloud

[![CI Build](https://github.com/cnopslabs/ocloud/actions/workflows/build.yml/badge.svg)](https://github.com/cnopslabs/ocloud/actions/workflows/build.yml)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cnopslabs/ocloud?sort=semver)
[![Downloads](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cnopslabs/ocloud/main/.github/badges/downloads.json&style=flat&logo=github&logoColor=white&label=downloads&labelColor=2f363d&color=brightgreen&cacheSeconds=3600)](https://github.com/cnopslabs/ocloud/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/cnopslabs/ocloud)](https://goreportcard.com/report/github.com/cnopslabs/ocloud)
[![Go Coverage](https://github.com/cnopslabs/ocloud/wiki/coverage.svg)](https://raw.githack.com/wiki/cnopslabs/ocloud/coverage.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast CLI for exploring Oracle Cloud Infrastructure (OCI). You can search and browse resources in an interactive TUI, and reach private resources through bastion tunnels. It uses your existing OCI CLI configuration.

## Install

```bash
brew tap cnopslabs/ocloud https://github.com/cnopslabs/ocloud
brew install ocloud
```

Or download a binary from [Releases](https://github.com/cnopslabs/ocloud/releases) and put it on your `PATH`. On macOS, clear the quarantine flag with `xattr -d com.apple.quarantine ocloud`. To build from source, run `make build && make install`.

**Requirements:** a configured [OCI CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm#Quickstart). You also need `kubectl` for OKE and an SSH key pair in `~/.ssh` for bastion sessions.

## Quick start

```bash
ocloud                                   # show current config and commands
ocloud config session authenticate       # log in (keeps the session refreshed)
ocloud compute instance search prod      # fuzzy search
ocloud network vcn list                  # interactive TUI
ocloud database autonomous get --json    # JSON for scripting
ocloud identity bastion create           # guided bastion session / tunnel
```

## Commands

Most resources support the same four verbs:

| Verb | Does |
|------|------|
| `get` | Paginated table (`--limit/-m`, `--page/-p`) |
| `list` | Interactive TUI picker |
| `search <query>` | Fuzzy, prefix and substring matching |
| `--all` / `-A` | Include related details (where supported) |

| Area | Resources (aliases) |
|------|---------------------|
| `compute` (`comp`) | `instance` (`inst`), `image` (`img`), `oke` |
| `database` (`db`) | `autonomous` (`adb`), `heatwave` (`hw`), `cache-cluster` (`cc`) |
| `network` (`net`) | `vcn`, `subnet` (`sub`; uses `find` instead of `search`), `load-balancer` (`lb`), `network-load-balancer` (`nlb`) |
| `identity` (`ident`) | `compartment` (`cmp`), `policy` (`pol`), `dynamic-group` (`dg`), `bastion` (`b`) |
| `storage` (`stg`) | `object-storage` (`os`), which also has `upload` and `download` |
| `config` (`conf`) | `session authenticate`, `info map-file`, `setup` |

Examples:

```bash
ocloud db hw s 8.4 -j                       # search HeatWave, JSON output
ocloud net vcn get -G -S -N -R -L           # VCNs with gateways, subnets, NSGs, route tables, security lists
ocloud ident cmp get -T                     # compartments across the whole tenancy
ocloud ident pol search monitor --scope tenancy
ocloud stg os upload                        # pick a bucket and file; multipart for files over 10 MiB
```

Identity commands (`compartment`, `policy`, `dynamic-group`) accept `--scope compartment|tenancy` or `-T` for tenancy scope.

**Global flags:** `-c/--compartment`, `-t/--tenancy-id`, `--tenancy-name`, `-j/--json`, `-d/--debug`, `--log-level`, `--color`, `-v/--version`. Run `ocloud <command> --help` for details.

In the TUI, `q`, `Esc` or `Ctrl+C` quits.

## Bastion sessions

`ocloud identity bastion create` walks you through choosing a bastion, a target, a session type, a resource and an SSH key. Tunnels run in the background and keep running after the CLI exits.

| Target | Session types | Default local port |
|--------|---------------|--------------------|
| Compute instance | Managed SSH, port forwarding, RDP, SCP upload/download | 5901 (PF), 3389 (RDP) |
| Autonomous DB | Port forwarding | 1521 |
| HeatWave MySQL | Port forwarding | 3306 |
| OCI Cache (Redis/Valkey) | Port forwarding | 6379 |
| OKE cluster | Managed SSH to node, port forwarding to API server (offers to write the kubeconfig) | 6443 |
| Load balancer (L7/L4) | Port forwarding | you choose |

- Local ports below 1024 (such as 443) ask for your sudo password first.
- Logs go to `~/.oci/sessions/<profile>/logs/` and tunnel state to `~/.oci/sessions/<profile>/tunnels/`.
- **Network requirement:** the target's subnet (security list or NSG) must allow TCP ingress from the bastion's private endpoint IP on the target port (22, 3389, 5901, and so on). Your public IP must also be in the bastion's client CIDR allowlist. ocloud only checks that the bastion and target share a VCN. "Tunnel is ready" means the local port is listening, not that the target answers. If your client can't connect, look for `open failed: connect failed` in the tunnel log.

Example: query a private Autonomous DB.

```bash
ocloud identity bastion create   # Database → Autonomous → pick ADB → port 1521
sqlplus admin@localhost:1521/mydb_high
```

## OKE tokens without the OCI CLI

`ocloud oke-token` is a kubectl exec credential plugin that generates OKE tokens natively, replacing `oci ce cluster generate-token`. To use it, point a kubeconfig user at ocloud:

```yaml
users:
- name: my-oke-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: ocloud
      args: [oke-token, --cluster-id, ocid1.cluster.oc1..., --region, us-ashburn-1]
```

It uses your session token profile (`OCI_CLI_PROFILE` or `--profile`; `--auth api_key` for API-key profiles). If the session has expired, it exits with an error instead of prompting. Kubeconfig entries written by `bastion create` still use the `oci` command for now.

## Configuration

Running `ocloud` without any arguments displays the configuration details and available commands.

Example output (values will vary by version, time, and your environment):

```
 ██████╗  ██████╗██╗      ██████╗ ██╗   ██╗██████╗
██╔═══██╗██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
██║   ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
██║   ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
╚██████╔╝╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
 ╚═════╝  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝

	      Version: v0.2.0

Configuration Details: Valid until <timestamp>
  OCI_CLI_PROFILE: DEFAULT
  OCI_TENANCY_NAME: cloudops
  OCI_COMPARTMENT_NAME: cnopslabsdev1
  OCI_AUTH_AUTO_REFRESHER: ON [<pid>]
  PORT_FORWARDING: ON [1521, 3306, 6443]
  OCI_TENANCY_MAP_PATH: /Users/<name>/.oci/.ocloud/tenancy-map.yaml

Interact with Oracle Cloud Infrastructure

Usage:
  ocloud [flags]
  ocloud [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  compute     Explore OCI compute services
  config      Manage ocloud CLI configurations file and authentication
  database    Explore OCI Database services
  help        Help about any command
  identity    Explore OCI identity services
  network     Explore OCI network services
  storage     Explore OCI Storage services
  version     Print the version information

Flags:
      --color                 Enable colored log messages.
  -c, --compartment string    OCI compartment name or OCID
  -d, --debug                 Enable debug logging
  -h, --help                  Show help
  -j, --json                  Output information in JSON format
      --log-level string      Set the log verbosity (e.g., info, debug) (default "info")
  -t, --tenancy-id string     OCI tenancy OCID
      --tenancy-name string   Tenancy name
  -v, --version               Print the ocloud CLI version
```

Settings are resolved in this order: flags, then environment variables, then `~/.oci/config`.

| Variable | Purpose | Default |
|----------|---------|---------|
| `OCI_CLI_PROFILE` | OCI config profile | `DEFAULT` |
| `OCI_CLI_TENANCY` | Tenancy OCID | from profile |
| `OCI_TENANCY_NAME` | Tenancy name (resolved through the tenancy map) | |
| `OCI_COMPARTMENT` | Compartment name | |
| `OCI_REGION` | Region | from profile |
| `OCI_TENANCY_MAP_PATH` | Tenancy map file | `~/.oci/.ocloud/tenancy-map.yaml` |

`ocloud config session authenticate [--filter us] [--realm OC1]` logs in and starts a background refresher. While it runs, `ocloud` shows `OCI_AUTH_AUTO_REFRESHER: ON [pid]`.

**Tenancy map.** This file maps friendly names to OCIDs. Create it with `ocloud config setup` and view it with `ocloud config info map-file`.

```yaml
- environment: Prod
  tenancy: cncloudps
  tenancy_id: ocid1.tenancy.oc1..aaaaaaaawdfste4i8fdsdsdkfasfds
  realm: OC1
  compartments:
    - sandbox
    - production
  regions:
    - us-chicago-1
    - us-ashburn-1
```

## Development

```bash
make build   # bin/ocloud
make test    # unit tests with coverage
make lint    # golangci-lint (also: fmt, vet, vuln)
./test_ocloud.sh   # smoke-test every command against a live tenancy
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture and standards. Report bugs and request features through [Issues](https://github.com/cnopslabs/ocloud/issues/new/choose). With a bug report, include `ocloud version` and the output of `--log-level debug`, with secrets redacted. Ask questions in [Discussions](https://github.com/cnopslabs/ocloud/discussions).

## License

MIT. See [LICENSE](LICENSE). Third-party notices, including the OCI Go SDK (UPL-1.0 / Apache-2.0), are in [NOTICE](NOTICE) and [third_party/](third_party/).
