//! The Requests tab: nodes waiting to be admitted to the mesh.
//!
//! The other end of the Security tab's "Join a mesh" panel — that one asks,
//! this one decides. A request is a node's public keys and its MAC, and
//! approving it is a statement that those belong together and belong here; the
//! key is therefore on screen before either button is, because it is what is
//! being vouched for.
//!
//! # Admitting a device also says for how long
//!
//! The lifetime sits on the row rather than in the enrollment policy, because
//! a fleet is not uniform: a sensor bolted to a structure and a laptop borrowed
//! for an afternoon reach this queue through the same door, and the lifetime is
//! the one thing that should differ between admitting them. The policy value
//! stays as the default an operator can just take — named on the option rather
//! than hidden behind the word "default", so taking it is still a choice made
//! knowingly.
//!
//! Short is the right instinct and the reason is not tidiness: a mesh removes a
//! node mainly by letting its certificate expire, and a long lifetime trades
//! that for an active revocation flood that has to reach the node.
//!
//! # An empty queue is not an absent one
//!
//! Both render as no rows, and they are different facts: one says nobody is
//! waiting, the other says this node does not take requests at all. The second
//! is [`super::ProviderGate`]'s answer; this tab only ever renders the first.
//!
//! # The rows may not be rebuilt by a poll
//!
//! They hold operator input — the lifetime chosen for a request that has not
//! been confirmed yet — and the snapshot behind them is replaced once a second.
//! A plain closure over it constructs fresh rows every second, whose
//! `signal(...)` fields are re-created at their defaults: the selection is
//! silently reset under a hand that is on its way to the Approve button. The
//! rows are therefore driven from a [`Memo`] over the narrowest projection they
//! need — the queue itself and the policy lifetime — since a memo re-runs but
//! only *notifies* when its own value changes. Widening that projection to
//! something that moves on its own restores the bug, and no markup test can see
//! it. [`super::enrollment`] carries the same warning for the same reason.

use leptos::prelude::*;
use wayfinder_protos::wayfinder::v1alpha::PendingCsr;

use crate::api::approve_csr;
use crate::api::deny_csr;
use crate::clock::now_unix;
use crate::components::dashboard::use_dashboard;
use crate::components::provider::ProviderGate;
use crate::components::provider::confirmation;
use crate::components::provider::report_failure;
use crate::components::widgets::Empty;
use crate::components::widgets::Panel;
use crate::components::widgets::Pending;
use crate::format;

/// The lifetimes offered on the row, as `(option value, label)`.
///
/// Values are seconds, and the labels are what an operator actually says out
/// loud. A month is 30 days and a year is 365: a certificate lifetime is
/// counted against a wall clock, and a "month" whose length depends on which
/// month it started in is not a quantity the provider can be handed.
///
/// The list stops at ten years because that is the provider's own cap
/// ([`wayfinder::config::MAX_CERT_TTL_SECS`]); an authority configured to allow
/// more takes it from `wayfinderctl`, not from a menu that would offer every
/// operator a certificate outliving the mesh.
const PRESETS: &[(u64, &str)] = &[
    (86_400, "1 day"),
    (7 * 86_400, "1 week"),
    (30 * 86_400, "1 month"),
    (90 * 86_400, "3 months"),
    (365 * 86_400, "1 year"),
    (10 * 365 * 86_400, "10 years"),
];

/// The `<select>` value that stands for "whatever the policy says", which is
/// not a number of seconds and must not be parsed as one.
const DEFAULT_CHOICE: &str = "";

/// The `<select>` value that reveals the date field.
const DATE_CHOICE: &str = "date";

/// How the confirmation dialog says the lifetime an approval would grant.
///
/// A phrase rather than a formatted duration because a *date* cannot honestly
/// become one: [`format::duration_secs`] refuses to round — a certificate
/// lifetime is a security setting, and "about a year" is not one — so the
/// seconds between now and the end of some day in 2027 render as the exact
/// count, which is true, unreadable, and not what the operator picked. The
/// date they picked is the thing to say back to them.
///
/// `ttl_secs` is the resolved lifetime the provider would be sent, `None`
/// meaning its policy default.
fn lifetime_phrase(
    choice: &str,
    date: &str,
    ttl_secs: Option<u64>,
    policy_ttl_secs: Option<u64>,
) -> String {
    if choice == DATE_CHOICE {
        // UTC is stated because that is what the date means here:
        // `format::unix_end_of_day` reads it as a UTC day, and the operator's
        // own timezone may put its end on either side of midnight.
        return format!("until the end of {date} UTC");
    }
    match ttl_secs {
        // The preset's own label, not the duration it works out to: the dialog
        // reading "for 365 days" over an option that said "1 year" invites the
        // reader to wonder which of the two they actually pressed.
        Some(secs) => match PRESETS.iter().find(|(preset, _)| *preset == secs) {
            Some((_, label)) => format!("for {label}"),
            None => format!("for {}", format::duration_secs(secs)),
        },
        // Named, not called "the default": an operator taking it should still
        // know what they took, the same reason the option itself spells it out.
        None => policy_ttl_secs.map_or_else(
            || "for this mesh's default lifetime".to_string(),
            |secs| format!("for {} — this mesh's default", format::duration_secs(secs)),
        ),
    }
}

/// Which decision a confirmed [`Pending`] carries out.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Decision {
    /// Admit the node with this MAC to the mesh, with a certificate valid for
    /// this many seconds — `None` taking the provider's policy default.
    Approve(Vec<u8>, Option<u64>),
    /// Refuse the request from the node with this MAC.
    Deny(Vec<u8>),
}

/// Render the Requests tab.
#[component]
pub fn Requests() -> impl IntoView {
    let dash = use_dashboard();
    let pending = RwSignal::new(None::<Pending<Decision>>);

    // Memoised, and kept as narrow as the rows need; see the module docs.
    let queue = Memo::new(move |_| {
        dash.snapshot.with(|s| {
            let s = s.as_ref();
            (
                s.and_then(|s| s.pending_csrs.clone()).map(|p| p.pending),
                s.and_then(|s| s.security.as_ref())
                    .and_then(|sec| sec.enrollment.as_ref())
                    .map(|policy| policy.cert_ttl_secs),
            )
        })
    });

    let confirm = move |decision: Decision| {
        let verb = match &decision {
            Decision::Approve(..) => "Approving",
            Decision::Deny(_) => "Denying",
        };
        leptos::task::spawn_local(async move {
            let result = match decision {
                Decision::Approve(mac, ttl_secs) => approve_csr(mac, ttl_secs).await,
                Decision::Deny(mac) => deny_csr(mac).await,
            };
            report_failure(dash, verb, result);
        });
    };

    view! {
        <ProviderGate>
            {move || {
                let (requests, policy_ttl_secs) = queue.get();
                let requests = requests.unwrap_or_default();
                let count = requests.len();
                view! {
                    <Panel
                        title="Requests to join"
                        subtitle=Signal::derive(move || format!("{count} waiting"))
                    >
                        {if requests.is_empty() {
                            view! { <Empty message="No nodes are waiting to join." /> }.into_any()
                        } else {
                            requests
                                .into_iter()
                                .map(|csr| {
                                    view! {
                                        <Request
                                            csr=csr
                                            policy_ttl_secs=policy_ttl_secs
                                            pending=pending
                                        />
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }}
                    </Panel>
                }
            }}
            {confirmation(pending, confirm)}
        </ProviderGate>
    }
}

/// One node waiting to be admitted: what it is asking with, for how long it
/// would be admitted, and the two decisions.
#[component]
fn Request(
    /// The request as of the last poll.
    csr: PendingCsr,
    /// The lifetime this provider's policy would apply, when it reported one.
    policy_ttl_secs: Option<u64>,
    /// Where a staged confirmation is written for the dialog to pick up.
    pending: RwSignal<Option<Pending<Decision>>>,
) -> impl IntoView {
    let dash = use_dashboard();
    let approve_mac = csr.node_mac.clone();
    let deny_mac = csr.node_mac.clone();
    // The selected preset (seconds as text), `DEFAULT_CHOICE`, or
    // `DATE_CHOICE`. Text rather than a typed enum because it is round-tripping
    // through a DOM `<select>`, and the one place it becomes a number is
    // guarded below.
    let (choice, set_choice) = signal(DEFAULT_CHOICE.to_string());
    let (date, set_date) = signal(String::new());
    let field_id = format!("wf-csr-ttl-{}", format::id(&csr.node_mac));

    // Resolve the row's controls into what the provider is actually told, or
    // into the reason it cannot be. `Err` is a message for the operator: the
    // approval does not go out, so a date nobody can honour never becomes a
    // certificate that expired on arrival.
    let chosen_ttl = move || -> Result<Option<u64>, String> {
        let choice = choice.get();
        if choice == DEFAULT_CHOICE {
            return Ok(None);
        }
        if choice != DATE_CHOICE {
            // Every other value came from `PRESETS`, so a parse failure means
            // the DOM handed back something this code never put there. Falling
            // back to the policy default is the one safe reading of that: it
            // admits the node for a lifetime the provider already stands
            // behind, rather than for a number nobody chose.
            return Ok(choice.parse().ok());
        }
        let Some(expires) = format::unix_end_of_day(date.get().trim()) else {
            return Err("Pick the date the certificate should expire on.".to_string());
        };
        // Zero would mean "this browser has no clock", and a lifetime computed
        // from a clock that does not exist is a number, not an answer.
        let now = now_unix();
        if now == 0 {
            return Err(
                "This browser could not read a clock, so a date cannot be turned into a \
                 lifetime. Pick one of the listed lifetimes instead."
                    .to_string(),
            );
        }
        expires
            .checked_sub(now)
            .filter(|secs| *secs > 0)
            .ok_or_else(|| "That date has already passed.".to_string())
            .map(Some)
    };

    let stage_approval = move |_| {
        let ttl_secs = match chosen_ttl() {
            Ok(ttl_secs) => ttl_secs,
            Err(why) => {
                dash.error.set(Some(why));
                return;
            }
        };
        let lifetime = lifetime_phrase(&choice.get(), &date.get(), ttl_secs, policy_ttl_secs);
        pending.set(Some(Pending {
            prompt: format!(
                "Admit {} to the mesh {lifetime}? It will be able to route traffic \
                 until its certificate expires.",
                format::id(&approve_mac),
            ),
            verb: "Approve",
            destructive: false,
            kind: Decision::Approve(approve_mac.clone(), ttl_secs),
        }));
    };

    view! {
        <div class="wf-csr">
            <div class="wf-csr-id">
                <span class="wf-mono">{format::id(&csr.node_mac)}</span>
                <span class="wf-csr-key wf-mono">{format::key(&csr.ed_pubkey)}</span>
                <span class="wf-csr-when">
                    "requested " {format::timestamp(csr.requested_at)}
                </span>
            </div>
            <div class="wf-csr-actions">
                <label class="wf-setting-label" for=field_id.clone()>
                    "Valid for"
                </label>
                <select
                    id=field_id
                    class="wf-input"
                    on:change=move |ev| set_choice.set(event_target_value(&ev))
                >
                    <option value=DEFAULT_CHOICE>
                        {policy_ttl_secs
                            .map_or_else(
                                || "This mesh's default".to_string(),
                                |secs| {
                                    format!("This mesh's default ({})", format::duration_secs(secs))
                                },
                            )}
                    </option>
                    {PRESETS
                        .iter()
                        .map(|(secs, label)| {
                            view! { <option value=secs.to_string()>{*label}</option> }
                        })
                        .collect_view()}
                    <option value=DATE_CHOICE>"Until a date…"</option>
                </select>
                {move || {
                    (choice.get() == DATE_CHOICE)
                        .then(|| {
                            view! {
                                <input
                                    class="wf-input"
                                    type="date"
                                    aria-label="Expiry date"
                                    prop:value=move || date.get()
                                    on:input=move |ev| set_date.set(event_target_value(&ev))
                                />
                            }
                        })
                }}
                <button class="wf-button wf-button-primary" on:click=stage_approval>
                    "Approve"
                </button>
                <button
                    class="wf-button"
                    on:click=move |_| {
                        pending
                            .set(
                                Some(Pending {
                                    prompt: format!(
                                        "Refuse {}'s request to join?",
                                        format::id(&deny_mac),
                                    ),
                                    verb: "Deny",
                                    destructive: false,
                                    kind: Decision::Deny(deny_mac.clone()),
                                }),
                            )
                    }
                >
                    "Deny"
                </button>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preset reads as the duration it is, which is what the option said.
    #[test]
    fn a_preset_is_stated_as_its_duration() {
        assert_eq!(
            lifetime_phrase("31536000", "", Some(31_536_000), Some(86_400)),
            "for 1 year",
            "the option's own words, not the 365 days it works out to"
        );
    }

    /// Taking the default still names the value taken, so an operator who
    /// pressed Approve without touching the chooser knows what they granted.
    #[test]
    fn the_default_names_the_policy_value() {
        assert_eq!(
            lifetime_phrase(DEFAULT_CHOICE, "", None, Some(86_400)),
            "for 1 day — this mesh's default"
        );
        // A provider that reported no policy at all still gets a sentence.
        assert_eq!(
            lifetime_phrase(DEFAULT_CHOICE, "", None, None),
            "for this mesh's default lifetime"
        );
    }

    /// A date is stated as the date, never as the seconds it works out to.
    ///
    /// This is the whole reason the phrase exists: the interval between now and
    /// the end of an arbitrary day is not a whole number of anything, and
    /// `duration_secs` does not round, so the dialog read "for 25684719
    /// seconds" — true, unreadable, and not what was picked.
    #[test]
    fn a_date_is_stated_as_the_date() {
        let phrase = lifetime_phrase(DATE_CHOICE, "2027-06-30", Some(25_684_719), Some(86_400));
        assert_eq!(phrase, "until the end of 2027-06-30 UTC");
        assert!(
            !phrase.contains("25684719"),
            "a date must never be read back as a raw second count: {phrase}"
        );
    }
}
