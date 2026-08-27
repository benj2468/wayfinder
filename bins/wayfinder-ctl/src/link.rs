//! Everything about one mesh interface: what it is doing, and what it should
//! do instead.
//!
//! These were seven separate top-level commands — `links`, `link-features`,
//! `ogm-schedule`, `link-enable`, `link-disable`, `set-link-features`,
//! `set-trickle-config` — in three different naming shapes, which put the read
//! of a setting and the write of it several screens apart in `--help`. They are
//! one subject, and an operator works on them as one: look at the table, change
//! the row.
//!
//! Everything here is addressed by `--iface`, the interface's index in
//! registration order, as `list`/`features`/`schedule` all report it. None of
//! the writes can provision a new interface; they reconfigure one the node
//! already has, in memory only, and nothing here survives a restart.

use anyhow::Context;
use clap::Subcommand;
use wayfinder_client::Client;
use wayfinder_protos::wayfinder::v1alpha::LinkFeatures;
use wayfinder_protos::wayfinder::v1alpha::link_features::TxKeepaliveUpdate;

use crate::output;
use crate::output::OutputFormat;

/// The per-interface reads and runtime writes.
#[derive(Subcommand, Debug)]
pub enum LinkCommand {
    /// The per-(neighbor, interface) link-quality table.
    List,
    /// The current per-interface participation-feature state (the tx/rx
    /// OGM/data gates and keep-alive cadence), with a derived on/off/mixed
    /// status per interface.
    Features,
    /// The per-interface adaptive OGM emission schedule: the live Trickle
    /// interval and the bounds `link trickle` sets.
    Schedule,
    /// Override one interface's participation features. Each flag is optional
    /// (`--tx-ogm true|false`, etc.): omit it to leave that gate unchanged, so
    /// you can flip one capability without restating the others.
    /// `--tx-keepalive-interval-ms`/`--tx-keepalive-disable` behave the same
    /// way but are mutually exclusive with each other (a cadence to arm, or a
    /// bare disable). Applied in memory only — it does not persist across a
    /// restart.
    Set {
        /// Index of the interface to reconfigure, in registration order.
        #[arg(long)]
        iface: u32,
        /// Send OGMs (own + re-flooded) onto this link.
        #[arg(long)]
        tx_ogm: Option<bool>,
        /// Receive OGMs on this link and learn routes from them.
        #[arg(long)]
        rx_ogm: Option<bool>,
        /// Send data-plane traffic (unicast/multicast/broadcast) onto this
        /// link. Also governs route re-advertisement.
        #[arg(long)]
        tx_data: Option<bool>,
        /// Accept data-plane traffic (unicast/multicast/broadcast) on this
        /// link.
        #[arg(long)]
        rx_data: Option<bool>,
        /// Arm (or re-arm) keep-alive heartbeat transmission on this link at
        /// this cadence, in milliseconds. Mutually exclusive with
        /// `--tx-keepalive-disable`; omit both to leave the schedule
        /// unchanged.
        #[arg(long, conflicts_with = "tx_keepalive_disable")]
        tx_keepalive_interval_ms: Option<u64>,
        /// Disable keep-alive heartbeat transmission on this link. Mutually
        /// exclusive with `--tx-keepalive-interval-ms`.
        #[arg(long)]
        tx_keepalive_disable: bool,
    },
    /// Set the Trickle/OGM emission bounds for one mesh interface, the values
    /// `link schedule` reports. Applied in memory only — it does not persist
    /// across a restart. Resets the interface's live Trickle timer, discarding
    /// any backoff already grown toward the old bound — expect a burst of OGMs
    /// shortly after this on a live interface.
    Trickle {
        /// Index of the interface to reconfigure, in registration order.
        #[arg(long)]
        iface: u32,
        /// New backoff floor (Trickle i_min), in milliseconds.
        #[arg(long)]
        min_ms: u32,
        /// New backoff ceiling (Trickle i_max), in milliseconds.
        #[arg(long)]
        max_ms: u32,
    },
    /// Turn a link fully on: set all four participation gates (tx_ogm, rx_ogm,
    /// tx_data, rx_data) to true. Does not re-arm keep-alive — there is no
    /// prior cadence to restore, so a link disabled with an armed keep-alive
    /// stays keep-alive-silent after enabling; arm it explicitly with
    /// `link set --tx-keepalive-interval-ms` if wanted.
    Enable {
        /// Index of the interface to enable, in registration order.
        #[arg(long)]
        iface: u32,
    },
    /// Turn a link fully off: set all four participation gates to false and
    /// disarm keep-alive transmission, so a disabled link goes fully silent
    /// rather than continuing to send heartbeats. This is a routing-layer
    /// silence, not a transport shutdown — the underlying socket/serial/radio
    /// stays open and polled.
    Disable {
        /// Index of the interface to disable, in registration order.
        #[arg(long)]
        iface: u32,
    },
}

/// Dispatch one `link` subcommand against an already-connected `client`.
pub async fn run(
    cmd: LinkCommand,
    client: &mut Client,
    fmt: OutputFormat,
) -> anyhow::Result<String> {
    Ok(match cmd {
        LinkCommand::List => output::link_quality_table(&client.link_quality_table().await?, fmt)?,
        LinkCommand::Features => {
            output::link_features_table(&client.link_features_table().await?, fmt)?
        }
        LinkCommand::Schedule => output::ogm_schedule(&client.ogm_schedule().await?, fmt)?,
        LinkCommand::Set {
            iface,
            tx_ogm,
            rx_ogm,
            tx_data,
            rx_data,
            tx_keepalive_interval_ms,
            tx_keepalive_disable,
        } => {
            // `conflicts_with` stops the both-given case at the CLI layer, but
            // this function is also reachable directly from a test, so the
            // rule is enforced here too rather than only in the grammar.
            let tx_keepalive_update = match (tx_keepalive_disable, tx_keepalive_interval_ms) {
                (true, Some(_)) => anyhow::bail!(
                    "--tx-keepalive-disable and --tx-keepalive-interval-ms are mutually exclusive"
                ),
                (true, None) => Some(TxKeepaliveUpdate::TxKeepaliveDisabled(true)),
                (false, Some(ms)) => Some(TxKeepaliveUpdate::TxKeepaliveIntervalMs(ms)),
                (false, None) => None,
            };
            client
                .set_link_features(LinkFeatures {
                    iface_idx: iface,
                    tx_ogm,
                    rx_ogm,
                    tx_data,
                    rx_data,
                    tx_keepalive_update,
                })
                .await
                .context("failed to set link features")?;
            "link features updated".to_string()
        }
        LinkCommand::Trickle {
            iface,
            min_ms,
            max_ms,
        } => {
            client
                .set_trickle_config(iface, min_ms, max_ms)
                .await
                .context("failed to set trickle config")?;
            "trickle config updated".to_string()
        }
        LinkCommand::Enable { iface } => {
            client
                .set_link_features(all_gates(iface, true, None))
                .await
                .context("failed to enable link")?;
            format!("link {iface} enabled")
        }
        LinkCommand::Disable { iface } => {
            client
                .set_link_features(all_gates(
                    iface,
                    false,
                    Some(TxKeepaliveUpdate::TxKeepaliveDisabled(true)),
                ))
                .await
                .context("failed to disable link")?;
            format!("link {iface} disabled")
        }
    })
}

/// Build a [`LinkFeatures`] setting all four participation gates to `on`, with
/// `keepalive` as the keep-alive instruction.
///
/// Shared by `enable` and `disable` so the two stay each other's exact inverse
/// on the gates; they differ only in the keep-alive half, which is deliberately
/// asymmetric (see the `Enable` and `Disable` doc comments).
fn all_gates(iface: u32, on: bool, keepalive: Option<TxKeepaliveUpdate>) -> LinkFeatures {
    LinkFeatures {
        iface_idx: iface,
        tx_ogm: Some(on),
        rx_ogm: Some(on),
        tx_data: Some(on),
        rx_data: Some(on),
        tx_keepalive_update: keepalive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `enable` and `disable` must set all four gates, and must be inverses on
    /// them — the whole point of the pair. Keep-alive is the one asymmetry.
    #[test]
    fn enable_and_disable_are_inverses_on_every_gate() {
        let on = all_gates(2, true, None);
        let off = all_gates(2, false, Some(TxKeepaliveUpdate::TxKeepaliveDisabled(true)));
        assert_eq!(on.iface_idx, 2);
        assert_eq!(
            (on.tx_ogm, on.rx_ogm, on.tx_data, on.rx_data),
            (Some(true), Some(true), Some(true), Some(true))
        );
        assert_eq!(
            (off.tx_ogm, off.rx_ogm, off.tx_data, off.rx_data),
            (Some(false), Some(false), Some(false), Some(false))
        );
        assert!(on.tx_keepalive_update.is_none());
        assert!(off.tx_keepalive_update.is_some());
    }
}
