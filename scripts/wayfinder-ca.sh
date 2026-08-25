#!/usr/bin/env bash
#
# Lifecycle for the cloud certificate authority: provision the instance,
# install NixOS onto it, provision its secrets, and update it afterwards.
#
# The design and the reasoning behind the posture live in
# docs/design/implemented/11-cloud-auth-provider.md; the first-time runbook,
# including how the mesh root of trust is minted, is infra/oracle/README.md.
# This script is the same sequence, made repeatable.
#
# Two things it deliberately does NOT do:
#
#   * It never generates the mesh root seed. That is a one-time, offline act
#     whose output is the mesh itself — see the README's step 1. A script that
#     silently minted a new root of trust on a re-run would be a foot-gun of
#     the worst kind.
#   * It never edits nix/machines/wayfinder-ca/common.nix. The mesh id, the
#     authorised SSH key and the host platform are declarative configuration
#     that belongs in git, not settings a deploy script pokes at.
#
#   ./scripts/wayfinder-ca.sh <command>
#
# Commands:
#   provision   Create or reconcile the cloud instance      (tofu apply)
#   install     Install NixOS over the stock image          (DESTRUCTIVE, once)
#   secrets     Copy the offline-minted trust material onto the node
#   update      Roll out a config/code change               (nixos-rebuild)
#   verify      Prove the CA answers and the tunnel plane is serving
#   status      Where it is and what it is doing
#   user-add    Create a dashboard sign-in account on the CA
#   dashboard   Forward the web dashboard to localhost
#   vpn         Show the tunnel control plane and its registered peers
#   headplane   Forward the break-glass VPN admin UI to localhost
#   destroy     Tear the whole deployment down              (DESTRUCTIVE)
#
# Environment:
#   CA_SECRETS_DIR   Where the offline trust material lives (default ~/ca-secrets)
#   CA_SSH_USER      User for the *stock* image, pre-install (default ubuntu)
#   CA_ASSUME_YES    Set to 1 to skip the confirmation on destructive commands
#   CA_CF_TOKEN_FILE File holding the Cloudflare API token (default ~/.cf-token)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra/oracle"
SECRETS_DIR="${CA_SECRETS_DIR:-$HOME/ca-secrets}"
SSH_USER="${CA_SSH_USER:-ubuntu}"
FLAKE_ATTR=".#wayfinder-ca"
CF_TOKEN_FILE="${CA_CF_TOKEN_FILE:-$HOME/.cf-token}"

# The four files the node is provisioned with. Named here rather than inline so
# `secrets` and the preflight check cannot disagree about what is required.
SECRET_FILES=(root.seed identity.seed node.cert trust-anchor)

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }

need() {
    command -v "$1" >/dev/null 2>&1 \
        || die "$1 is not on PATH — run this from the repo's dev shell ('nix develop')"
}

# Verification output.
#
# A failing check prints what it means and what to do about it, and the run
# carries on rather than aborting: an operator wants the whole picture from one
# invocation, and "the management API answers but STUN does not" is a different
# problem from either half failing alone.
VERIFY_FAILURES=0

check_ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }

check_note() {
    local line
    for line in "$@"; do printf '        %s\n' "$line" >&2; done
    printf '\n' >&2
}

check_failed() {
    printf '  \033[31mFAIL\033[0m  %s\n' "$1" >&2
    shift
    check_note "$@"
    VERIFY_FAILURES=$((VERIFY_FAILURES + 1))
}

# Not a failure: something this machine could not determine. Counted separately
# because "we did not look" and "we looked and it is broken" call for opposite
# reactions, and conflating them is how a check becomes noise.
check_skipped() {
    printf '  \033[33mskip\033[0m  %s\n' "$1" >&2
    shift
    check_note "$@"
}

# Looked, did not like what it saw, and cannot prove the box is at fault. Also
# not counted: a check that fails the run on evidence this weak trains an
# operator to ignore the run.
check_warned() {
    printf '  \033[33mwarn\033[0m  %s\n' "$1" >&2
    shift
    check_note "$@"
}

# The tunnel endpoint, read out of the machine configuration rather than
# restated here: `services.wayfinder-headscale` derives the URL from the TLS
# mode, the name and the port, and that derivation is exactly what `update`
# deploys. A copy in this script could only ever be a second thing to keep in
# step, and the one that is wrong is the one you would debug against.
#
# Prints "<url> <hostname> <stun-port>", or nothing if evaluation fails.
vpn_settings() {
    # The `${...}` below is Nix interpolation inside the --apply expression, and
    # has to reach nix unexpanded — single quotes are the point, not an oversight.
    # shellcheck disable=SC2016
    (cd "$REPO_ROOT" && nix eval --raw \
        ".#nixosConfigurations.wayfinder-ca.config.services.wayfinder-headscale" \
        --apply 'c: "${c.endpoint} ${c.domain} ${toString c.stunPort}"' 2>/dev/null)
}

confirm() {
    [[ "${CA_ASSUME_YES:-0}" == "1" ]] && return 0
    printf '\033[33m%s\033[0m\n' "$1"
    read -r -p "Type 'yes' to continue: " reply
    [[ "$reply" == "yes" ]] || die "aborted"
}

# Read a password from the terminal into the named variable, echoing a '*' per
# character. Not `read -rs`: a silent prompt gives no sign that a paste from a
# password manager landed at all, and its terminal state does not survive a
# Ctrl-C — bash restores the tty only on a normal return, so an interrupt at the
# prompt leaves the shell running with echo off, typing nothing back.
#
# The saved `stty` settings are restored on every exit from this function,
# interrupt included, and the interrupt is then re-raised with the default
# disposition so Ctrl-C still ends the script the way the user meant it to.
read_password() {
    local __prompt="$1" __out="$2"
    local __pass="" __char __saved

    # Not a terminal (a pipe, or a test harness): take the line as given.
    if [[ ! -t 0 ]]; then
        IFS= read -r __pass || true
        printf -v "$__out" '%s' "$__pass"
        return 0
    fi

    __saved="$(stty -g)"
    trap 'stty "$__saved"; printf "\n" >&2; trap - INT; kill -INT $$' INT

    printf '%s' "$__prompt" >&2
    while IFS= read -rsn1 __char; do
        case "$__char" in
            # Enter: `read -n1` yields an empty string for the newline.
            "") break ;;
            # Backspace/delete: rub the last star off the screen too.
            $'\177'|$'\b')
                [[ -n "$__pass" ]] || continue
                __pass="${__pass%?}"
                printf '\b \b' >&2
                ;;
            # Ignore the remaining control characters rather than counting them
            # as password bytes — a paste can carry a stray \r, and an escape
            # sequence from an arrow key would otherwise land in the password.
            [[:cntrl:]]) ;;
            *)
                __pass+="$__char"
                printf '*' >&2
                ;;
        esac
    done
    printf '\n' >&2

    stty "$__saved"
    trap - INT
    printf -v "$__out" '%s' "$__pass"
}

# The instance's address, straight from OpenTofu state — never hardcoded, so
# this script keeps working after the address changes (it is a reserved IP, so
# it should not, but "should not" is not "cannot").
ca_ip() {
    # Checked separately from the query below so a missing tool does not
    # present as a missing deployment — they call for opposite fixes.
    need tofu
    local ip
    ip="$(cd "$INFRA_DIR" && tofu output -raw public_ip 2>/dev/null)" \
        || die "no public_ip in OpenTofu state — run '$0 provision' first"
    [[ -n "$ip" ]] || die "public_ip is empty — run '$0 provision' first"
    printf '%s' "$ip"
}

# `wayfinder-ctl` is not in the dev shell, so build it from this checkout and
# reuse the store path. Built once per invocation, not once per call.
CTL_CACHE=""
ctl() {
    if [[ -z "$CTL_CACHE" ]]; then
        info "building wayfinder-ctl from this checkout" >&2
        CTL_CACHE="$(nix build "$REPO_ROOT#wayfinder-ctl" --no-link --print-out-paths)/bin/wayfinder-ctl"
    fi
    "$CTL_CACHE" "$@"
}

require_secrets() {
    [[ -d "$SECRETS_DIR" ]] || die "no secrets directory at $SECRETS_DIR — see infra/oracle/README.md step 1"
    local missing=()
    for f in "${SECRET_FILES[@]}"; do
        [[ -f "$SECRETS_DIR/$f" ]] || missing+=("$f")
    done
    (( ${#missing[@]} == 0 )) || die "missing in $SECRETS_DIR: ${missing[*]} — see infra/oracle/README.md step 1"
}

# The Cloudflare API token, for the tunnel and the DNS records in infra/oracle.
#
# Read from a file rather than expected in the environment, because the failure
# mode of the environment is bad: OpenTofu's Cloudflare provider takes its
# credential from $CLOUDFLARE_API_TOKEN and nowhere else, so a token that lives
# only in a shell export is one fresh terminal, subshell or `sudo` away from an
# unauthenticated API call — which Cloudflare rejects as a bare
# `400 Missing X-Auth-Key, X-Auth-Email or Authorization headers`, naming
# neither the token nor the cause.
#
# An already-exported token still wins, so CI can inject its own.
load_cf_token() {
    if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        return 0
    fi

    if [[ -f "$CF_TOKEN_FILE" ]]; then
        # Stripped, not read verbatim: the newline an editor appends would
        # otherwise travel into the Authorization header and fail the request.
        local token; token="$(tr -d '[:space:]' < "$CF_TOKEN_FILE")"
        [[ -n "$token" ]] \
            || die "$CF_TOKEN_FILE is empty — it should hold the Cloudflare API token and nothing else"
        [[ "$(stat -c '%a' "$CF_TOKEN_FILE" 2>/dev/null)" =~ ^[0-7]00$ ]] \
            || warn "$CF_TOKEN_FILE is readable beyond its owner — 'chmod 600 $CF_TOKEN_FILE'"
        export CLOUDFLARE_API_TOKEN="$token"
        return 0
    fi

    # No token anywhere. Only a problem if this deployment actually has
    # Cloudflare resources to reconcile — one reached over an SSH forward has
    # none, and must not be made to invent a credential it never uses.
    if grep -Eq '^[[:space:]]*manage_(tunnel|dns)[[:space:]]*=[[:space:]]*true' \
        "$INFRA_DIR/terraform.tfvars" 2>/dev/null; then
        die "no Cloudflare API token, but terraform.tfvars manages Cloudflare resources.
Put the token in $CF_TOKEN_FILE (or export CLOUDFLARE_API_TOKEN).
It needs Zone:DNS:Edit on the zone and Account:Cloudflare Tunnel:Edit."
    fi
}

cmd_provision() {
    need tofu
    [[ -f "$INFRA_DIR/terraform.tfvars" ]] \
        || die "no $INFRA_DIR/terraform.tfvars — copy terraform.tfvars.example and fill it in"
    load_cf_token
    info "reconciling the cloud instance"
    (cd "$INFRA_DIR" && tofu init -input=false && tofu apply -input=false)
    info "public address: $(ca_ip)"
}

cmd_install() {
    need nixos-anywhere
    local ip; ip="$(ca_ip)"
    confirm "This ERASES the boot volume of $ip and installs NixOS over it.
Everything on that instance — including any CA state already there — is lost.
For a node that is already running NixOS, you want 'update', not 'install'."
    info "installing NixOS onto $ip (first build may be slow under emulation)"
    (cd "$REPO_ROOT" && nixos-anywhere --flake "$FLAKE_ATTR" --target-host "$SSH_USER@$ip" --no-disko-deps --build-on local)
    # The install replaces the entire OS, so the host generates fresh SSH host
    # keys and every later step would stop on REMOTE HOST IDENTIFICATION HAS
    # CHANGED. That warning is correct in general and noise here — we are the
    # ones who replaced the host — so retire the old entry rather than teaching
    # an operator to ignore a warning that exists to catch a real attack.
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    info "installed; the node will not start until '$0 secrets' has run"
}

cmd_secrets() {
    require_secrets
    local ip; ip="$(ca_ip)"
    info "provisioning trust material onto $ip"
    # First contact after an install: the host key is new and unknown. Accepted
    # on first use rather than prompted for, since this runs unattended
    # straight after `install` put that key there.
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes "root@$ip" true \
        || die "cannot reach root@$ip over SSH — has '$0 install' run?"
    # The directory is created here rather than trusted to exist: the node's
    # systemd unit cannot write it (it is outside ReadWritePaths, deliberately —
    # the node reads its root of trust and must not be able to rewrite it).
    ssh "root@$ip" 'install -d -m 0700 -o wayfinder -g wayfinder /var/lib/wayfinder-secrets'
    for f in "${SECRET_FILES[@]}"; do
        scp -q "$SECRETS_DIR/$f" "root@$ip:/var/lib/wayfinder-secrets/$f"
    done
    # The Cloudflare Tunnel credentials, when the deployment has a public
    # dashboard. Written by `tofu apply` (infra/oracle/tunnel.tf) rather than
    # minted by hand, and optional: a deployment reached only over an SSH
    # forward has no tunnel and no such file.
    if [[ -f "$SECRETS_DIR/cloudflared.json" ]]; then
        scp -q "$SECRETS_DIR/cloudflared.json" "root@$ip:/var/lib/wayfinder-secrets/cloudflared.json"
        info "tunnel credentials provisioned"
    fi
    ssh "root@$ip" '
        chown wayfinder:wayfinder /var/lib/wayfinder-secrets/*
        chmod 0400 /var/lib/wayfinder-secrets/*
        systemctl restart wayfinder.service
        systemctl is-active --quiet wayfinder.service'
    info "trust material in place; wayfinder.service restarted"
}

cmd_update() {
    need nixos-rebuild
    local ip; ip="$(ca_ip)"
    info "rolling out to $ip"
    # `switch`, not `boot`: a CA is stateless apart from files under
    # /var/lib/wayfinder, so there is nothing to drain and no reason to make an
    # operator wait for a reboot to pick up a change.
    #
    # Built locally and pushed. On an aarch64 workstation targeting the x86_64
    # E2 shape that build runs under binfmt emulation and is slow the first
    # time; it is still the right side to build on, since the instance has
    # 1 GB of RAM and would OOM.
    (cd "$REPO_ROOT" && nixos-rebuild switch --flake "$FLAKE_ATTR" --target-host "root@$ip")
    info "rolled out; 'wayfinder-ca.sh verify' to confirm it still answers"
}

# The tunnel plane over HTTPS. Curl's exit code says *which* hop failed, and
# the three hops fail for entirely different reasons — DNS that was never
# created, a security-list rule that is not there, a certificate that has not
# been issued yet — so they get three different sets of instructions rather
# than one "check your config".
verify_vpn_https() {
    local url="$1" host="$2" ip="$3" code=0

    curl -sf -o /dev/null --max-time 15 "$url/health" || code=$?
    if [[ "$code" == 0 ]]; then
        check_ok "$url/health answers, over a certificate that validates"
        return
    fi

    case "$code" in
        6)
            check_failed "$host does not resolve." \
                "The DNS record has not been created, or has not propagated yet." \
                "  dig +short $host                 # expect $ip" \
                "  (cd infra/oracle && tofu plan)   # is manage_dns true, and the vpn record in the plan?" \
                "Records here must be DNS-only (grey cloud). A proxied record resolves to" \
                "Cloudflare, which carries neither this port nor the UDP that STUN needs."
            ;;
        7 | 28)
            check_failed "nothing answered at $url." \
                "The name resolves, so this is a closed port rather than a missing record." \
                "Two firewalls sit in front of it, and both have to agree:" \
                "  (cd infra/oracle && tofu plan)             # the TCP/443 ingress rule" \
                "  ssh root@$ip 'ss -lnt | grep 443'          # is headscale bound at all?" \
                "  ssh root@$ip systemctl status headscale.service" \
                "A headscale that cannot obtain its certificate does not serve, so check" \
                "the certificate first if the unit is running but nothing is listening."
            ;;
        35 | 51 | 60)
            check_failed "$host answered, but its certificate did not validate." \
                "Almost always ACME: the certificate has not been issued yet, or was" \
                "issued for a different name than the one being asked for." \
                "  ssh root@$ip 'journalctl -u headscale | grep -i acme'" \
                "  curl -kvI $url/health            # what is actually being served" \
                "A first boot takes a minute or two. If it has been longer, check that" \
                "$host resolves to $ip from the public internet — Let's Encrypt validates" \
                "from outside, and it rate-limits failures to 5 per hostname per hour, so" \
                "fix DNS before restarting headscale to retry." \
                "Until this passes, no node can complete a tunnel handshake: tailscaled" \
                "refuses a plaintext DERP connection and loses STUN probing with it."
            ;;
        *)
            check_failed "could not reach $url/health (curl exit $code)." \
                "  curl -v $url/health" \
                "  ssh root@$ip systemctl status headscale.service"
            ;;
    esac
}

# STUN, which is the check most worth automating: losing it costs no
# connectivity at all, only latency, so nothing reports it.
verify_vpn_stun() {
    local host="$1" port="$2" ip="$3" replied

    if ! command -v nc >/dev/null 2>&1; then
        check_skipped "no nc on PATH, so udp/$port went unchecked." \
            "Run this from the repo's dev shell, or check it by hand from a machine" \
            "with outbound UDP:" \
            "  nc -zvu $host $port"
        return
    fi

    # The exact 40-byte binding request a Tailscale client sends, because that
    # is the only client this relay will ever serve — and it answers nothing
    # else. `ParseBindingRequest` in tailscale's net/stun requires a SOFTWARE
    # attribute whose value is the literal "tailnode", a FINGERPRINT as the
    # *last* attribute, and a matching CRC-32; anything else is dropped in
    # silence. A textbook-conformant client is refused too — `stunclient` from
    # stuntman reports "Binding test: fail" against a relay that is working
    # perfectly, and a bare 20-byte request that Google answers gets nothing
    # here. Both were mistaken for a broken relay before this was understood.
    #
    # Every byte is fixed, so it is spelled out rather than computed. To
    # regenerate (only needed if tailscale changes `software`, which would
    # change what real clients send too):
    #
    #   python3 -c '
    #   import struct, zlib
    #   txid = b"wayfinder-ca"
    #   body = struct.pack(">HH", 0x8022, 8) + b"tailnode"
    #   head = b"\x00\x01" + struct.pack(">H", len(body)+8) + b"\x21\x12\xa4\x42" + txid
    #   fp   = zlib.crc32(head+body) ^ 0x5354554e
    #   print("".join("\\x%02x" % b for b in head+body+struct.pack(">HHI",0x8028,4,fp)))'
    #
    # `nc -zu` is no substitute: it reports "succeeded" whenever no ICMP
    # port-unreachable comes back, so a black hole and a healthy relay print
    # exactly the same line.
    local request='\x00\x01\x00\x14\x21\x12\xa4\x42wayfinder-ca\x80\x22\x00\x08tailnode\x80\x28\x00\x04\xbc\x49\x66\xd7'
    # shellcheck disable=SC2059  # the bytes are the format string, by design
    replied="$(printf "$request" \
        | nc -u -w 5 "$host" "$port" 2>/dev/null | head -c 64 | wc -c)" || replied=0

    if [[ "${replied:-0}" -gt 0 ]]; then
        check_ok "the embedded relay answered a STUN binding request on udp/$port"
    else
        # A warning rather than a failure: silence is real evidence now that the
        # request is the one a client actually sends, but it is still not proof.
        # Any network on the path may have dropped the datagram, and plenty do.
        check_warned "no STUN response from $host:$port — could not confirm the relay answers." \
            "Rule out the path before the box: a dropped UDP datagram and a dead relay" \
            "look identical from here, and hotel and corporate networks drop plenty." \
            "  ssh root@$ip 'ss -lun | grep 3478'         # is the relay bound?" \
            "  ssh root@$ip 'journalctl -u headscale | grep -i stun'" \
            "  (cd infra/oracle && tofu plan)             # the UDP/3478 ingress rule" \
            "Do not reach for a generic STUN tool to double-check: this relay answers" \
            "only tailscale's dialect and drops a textbook-conformant request in silence," \
            "so stunclient and friends report failure against a healthy relay." \
            "If it really is down nothing breaks outright — every tunnel just relays" \
            "through the CA instead of hole-punching past the CGNAT this exists to defeat," \
            "which shows up as latency and in no log at all."
    fi
}

cmd_verify() {
    require_secrets
    local ip; ip="$(ca_ip)"
    VERIFY_FAILURES=0

    info "management API at $ip:7700"
    if ctl --connect "$ip:7700" \
        --identity "$SECRETS_DIR/identity.seed" \
        --cert "$SECRETS_DIR/node.cert" \
        node-info
    then
        check_ok "the management API answers and accepted this identity"
    else
        check_failed "the management API did not answer at $ip:7700." \
            "  ssh root@$ip systemctl status wayfinder.service" \
            "  ssh root@$ip 'journalctl -u wayfinder -n 50'" \
            "  (cd infra/oracle && tofu plan)   # the TCP/7700 ingress rule" \
            "If the unit is restarting in a loop, read the first lines of a start attempt:" \
            "the node refuses to run rather than serve for the wrong mesh, so a missing" \
            "secret or a mesh id that disagrees with the trust anchor stops it here." \
            "If SSH does not answer either, use Oracle's serial console — this box is" \
            "configured with console=ttyS0 for exactly that."
    fi

    if ctl --connect "$ip:7700" \
        --identity "$SECRETS_DIR/identity.seed" \
        --cert "$SECRETS_DIR/node.cert" \
        security
    then
        check_ok "the security state reads back"
    else
        check_failed "the node answered but would not report its security state." \
            "The connection authenticated, so this is authorization rather than reach:" \
            "the identity in $SECRETS_DIR must be an admin of this mesh." \
            "  $0 status                        # what the certificate actually carries"
    fi

    info "tunnel control plane"
    local settings url host stun
    settings="$(vpn_settings)" || settings=""
    read -r url host stun <<<"$settings" || true

    if [[ -z "${url:-}" ]]; then
        check_skipped "could not read the VPN settings out of the machine configuration." \
            "Everything below depends on knowing the name and port this deployment uses," \
            "which is read from the flake rather than restated in this script:" \
            "  nix eval .#nixosConfigurations.wayfinder-ca.config.services.wayfinder-headscale.endpoint" \
            "If that fails to evaluate, the deployment would not build either — fix it" \
            "before rolling anything out."
    else
        verify_vpn_https "$url" "$host" "$ip"
        verify_vpn_stun "$host" "$stun" "$ip"
    fi

    if (( VERIFY_FAILURES > 0 )); then
        die "$VERIFY_FAILURES check(s) failed — see above"
    fi
    info "the CA is reachable, authenticating, and coordinating tunnels"
}

cmd_status() {
    local ip; ip="$(ca_ip)"
    printf 'address:   %s\n' "$ip"
    printf 'mgmt API:  %s:7700\n' "$ip"
    # The identity clients pin with --node-key, read back off the certificate
    # rather than kept in a note that can drift from what is deployed.
    if [[ -f "$SECRETS_DIR/node.cert" ]]; then
        printf 'identity:\n'
        ctl cert show "$SECRETS_DIR/node.cert" | sed 's/^/  /'
    fi
    printf 'VPN:       %s:443 (headscale, TLS), STUN on udp/3478\n' "$ip"
    ssh -o ConnectTimeout=8 "root@$ip" \
        'systemctl is-active wayfinder.service wayfinder-web.service \
             headscale.service headplane.service; uptime' 2>/dev/null \
        || warn "could not reach the node over SSH"
}

cmd_user_add() {
    local username="${1:-}" ; shift || true
    [[ -n "$username" ]] || die "usage: $0 user-add <username> [--viewer]"
    local role="--admin"
    [[ "${1:-}" == "--viewer" ]] && role=""
    local ip; ip="$(ca_ip)"

    # `wayfinder-ctl user add` edits the authority's state file directly, so it
    # runs on the node and not here — and the node has to be stopped while it
    # does. The running process holds that state in memory and rewrites the
    # whole blob on its next change, so an edit underneath it would be
    # overwritten without a word.
    #
    # (There is an online path too — `CreateUser` over the management API,
    # which the dashboard's own Security tab uses — but it needs an
    # authenticated admin session, which is the thing this command exists to
    # bootstrap.)
    info "creating account '$username' on $ip (the CA restarts around this)"
    local password password2
    read_password "Password for $username: " password
    [[ -n "$password" ]] || die "empty password"
    read_password "Again: " password2
    [[ "$password" == "$password2" ]] || die "passwords do not match"

    # The password reaches the node over the SSH channel on stdin, never in
    # argv — argv is readable by every process on the host.
    # `$username` and `$role` are expanded here, on the client, which is what
    # SC2029 warns about — both are validated above precisely so that is safe.
    # The password is not expanded anywhere: it travels on stdin, never in
    # argv, which every process on either host can read.
    # shellcheck disable=SC2029
    printf '%s\n' "$password" | ssh "root@$ip" "
        set -e
        systemctl stop wayfinder.service
        wayfinder-ctl user add \\
            --state /var/lib/wayfinder/ca-state.json \\
            --username $username $role --password-stdin
        chown wayfinder:wayfinder /var/lib/wayfinder/ca-state.json
        systemctl start wayfinder.service"
    info "account created — scan the TOTP URI above into your authenticator"
}

cmd_dashboard() {
    local ip; ip="$(ca_ip)"
    info "forwarding http://127.0.0.1:8080 -> $ip (Ctrl-C to stop)"
    # The dashboard is bound to the node's loopback and must stay there while it
    # runs on the static credential: it performs no authentication of its own,
    # so whoever reaches the port inherits the identity it holds — which on this
    # node is an admin of the mesh root.
    #
    # 8081 at the far end: Headscale has 8080 there. The dashboard does not
    # compare ports when checking the Host header, so the mismatch is invisible
    # to it (see HostPolicy in bins/wayfinder-web/src/server.rs).
    ssh -N -L 8080:localhost:8081 "root@$ip"
}

cmd_vpn() {
    local ip; ip="$(ca_ip)"
    info "tunnel control plane on $ip"
    # Read straight off the box: Headscale's own view of who is registered is
    # the ground truth, and the reason to look here rather than at the
    # dashboard is usually that the dashboard is the thing not answering.
    #
    # Sent as a heredoc rather than a quoted argument so the script below is
    # ordinary shell — apostrophes and nested quoting included.
    ssh "root@$ip" bash -s <<'REMOTE' || warn "could not reach the tunnel control plane"
set -u

systemctl is-active headscale.service headplane.service \
    wayfinder-headscale-apikey.service || true

printf '\napi key expires: '
if [ -s /var/lib/wayfinder-headscale/api.key.expires ]; then
    date -d "@$(cat /var/lib/wayfinder-headscale/api.key.expires)"
else
    echo 'not minted yet'
fi

# The URL headscale advertises, read out of the config the daemon was actually
# started with: /etc/headscale/config.yaml is only a CLI stub (socket path,
# update check), and the real settings are a store path named in the unit.
unit_script=$(systemctl show -p ExecStart --value headscale.service \
    | sed -n 's/.*path=\([^;]*\);.*/\1/p' | tr -d ' ')
cfg=$(grep -oE -- '--config [^ ]+' "$unit_script" | head -1 | cut -d' ' -f2)
url=$(grep -E '^server_url:' "$cfg" | cut -d' ' -f2 | tr -d '"')
printf '\nserver_url: %s\n' "$url"

# TLS is the quiet failure on this box. The control plane answers fine without
# it while every tunnel handshake refuses, taking STUN probing down with it —
# so nodes register and then cannot reach each other, even on the same LAN.
case "$url" in
    https://*)
        echo 'certificate:'
        curl -sv --max-time 10 "$url/health" 2>&1 >/dev/null \
            | grep -E 'subject:|expire date:|SSL certificate verify' \
            | sed 's/^\* */  /' \
            || echo '  no TLS handshake — tunnels will not establish'
        ;;
    *)
        echo 'WARNING: serving plain HTTP. A tailscaled refuses a plaintext DERP'
        echo 'connection, so nodes will register and then fail to reach each other.'
        ;;
esac

printf '\n'
headscale nodes list
REMOTE
}

cmd_headplane() {
    local ip; ip="$(ca_ip)"
    info "forwarding http://127.0.0.1:3001/admin -> $ip (Ctrl-C to stop)"
    # Break-glass only. It is loopback-bound on the node deliberately, and the
    # forward is the friction that keeps it a fallback rather than a surface
    # anyone routes to — the day-to-day view is the dashboard's VPN panel.
    #
    # Sign in by pasting a Headscale API key; mint a throwaway one with
    #   ssh root@<ca> headscale apikeys create --expiration 24h
    # rather than reusing the node's, which has no expiry anyone is watching.
    ssh -N -L 3001:localhost:3000 "root@$ip"
}

cmd_destroy() {
    need tofu
    load_cf_token
    confirm "This DESTROYS the cloud instance and its boot volume.
The CA's issued-certificate log and revocations go with it. The mesh root seed
in $SECRETS_DIR survives, so the mesh can be rebuilt — but every certificate
this CA issued becomes unverifiable against a CA that no longer remembers it."
    (cd "$INFRA_DIR" && tofu destroy -input=false)
}

main() {
    local cmd="${1:-}"; shift || true
    case "$cmd" in
        provision) cmd_provision "$@" ;;
        install)   cmd_install "$@" ;;
        secrets)   cmd_secrets "$@" ;;
        update)    cmd_update "$@" ;;
        verify)    cmd_verify "$@" ;;
        status)    cmd_status "$@" ;;
        user-add)  cmd_user_add "$@" ;;
        dashboard) cmd_dashboard "$@" ;;
        vpn)       cmd_vpn "$@" ;;
        headplane) cmd_headplane "$@" ;;
        destroy)   cmd_destroy "$@" ;;
        ""|-h|--help|help)
            sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'
            ;;
        *) die "unknown command '$cmd' (try --help)" ;;
    esac
}

main "$@"
