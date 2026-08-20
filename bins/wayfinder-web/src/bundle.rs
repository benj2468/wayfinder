//! The `.wfauth` credential bundle: a session's key and certificate, as a file
//! somebody can keep.
//!
//! # What it is for
//!
//! Signing in needs the certificate authority; *using* a session does not (§8.3
//! of `docs/design/06-management-api-authentication.md`). A node verifies a
//! session certificate against the trust anchor it already holds, so a
//! credential minted while the provider was reachable keeps working after the
//! link to it is gone — but only for as long as the process that holds it
//! stays up, because the session store lives in memory and a dashboard restart
//! is a fresh sign-in.
//!
//! This is what closes that gap without persisting anything on the server. A
//! signed-in viewer downloads their own credential as one file, keeps it
//! wherever they keep secrets, and hands it back to a sign-in form later. The
//! dashboard then builds a session out of it with no contact with the provider
//! at all: the *node* is the only party consulted, and it is the party the
//! dashboard is pointed at anyway.
//!
//! # What is in it, and what may be trusted
//!
//! The payload is two fields — a 32-byte Ed25519 seed and the membership
//! certificate the provider signed for it. Everything else (`username`,
//! `capability`, the validity window) is a copy of what the certificate already
//! says, present so the file means something to a person who opens it in a text
//! editor months later. **None of it is trusted on the way back in.** The
//! capability shown after a bundle sign-in is recomputed from the certificate's
//! signed flags, and the certificate itself is only worth what the node makes
//! of it: a hand-edited flag byte breaks the mesh root's signature, and the
//! node refuses the connection.
//!
//! The one field with no certificate behind it is `username`, which is a label
//! for the header and nothing else. Editing it renames what the dashboard calls
//! you and changes no access whatsoever.
//!
//! # This is a private key in a file, and that is the point
//!
//! Everywhere else in this crate the browser never holds a key. This is the
//! deliberate exception: the whole feature is handing the *person* their
//! credential so it can outlive the process that minted it. It carries no
//! password of its own — encrypting it would need a second secret the person
//! has to keep anyway, and the design note is that they already have somewhere
//! to keep secrets. Two things follow, and both are enforced elsewhere:
//! the download is served only to the session it belongs to (`server.rs`), and
//! it expires exactly when that session's certificate does, which is why the
//! expiry is in the filename rather than buried in the file.

#[cfg(feature = "ssr")]
use anyhow::Context;
#[cfg(feature = "ssr")]
use anyhow::bail;
#[cfg(feature = "ssr")]
use serde::Deserialize;
#[cfg(feature = "ssr")]
use serde::Serialize;
#[cfg(feature = "ssr")]
use wayfinder_auth::CERT_VERSION;
#[cfg(feature = "ssr")]
use wayfinder_auth::Keypair;
#[cfg(feature = "ssr")]
use wayfinder_auth::MembershipCert;

/// The extension a bundle is downloaded and offered back with.
///
/// Named rather than spelled inline: the download filename, the file input's
/// `accept` filter and the tests all have to agree, and a mismatch between the
/// first two is a file picker that greys out the file it just produced.
pub const BUNDLE_EXTENSION: &str = "wfauth";

/// The layout version stamped on every bundle this build writes, and the only
/// one it reads.
///
/// A refusal names the version it found, because the useful answer to a file
/// from a newer dashboard is "upgrade this one", not "the file is corrupt".
pub const BUNDLE_VERSION: u32 = 1;

/// The longest account name a bundle may carry.
///
/// The authority puts no limit on a user name, so this is not a mirror of one
/// — it is a bound on what an *uploaded file* can push into places that are
/// not sized for it: a log line, a `Content-Disposition` header, and the page
/// header it is rendered into. Generous enough that no plausible account name
/// meets it, which is the point: it is a guard, not a policy.
#[cfg(feature = "ssr")]
const MAX_USERNAME_LEN: usize = 128;

/// Where the credential download is served from.
///
/// Ungated, and it has to be: the header's `<a href>` is rendered by the
/// browser build and the route is registered by the server build, so a
/// constant either side could not see is a constant they could disagree about
/// — which is a download button that 404s and nothing that would catch it.
///
/// Under `/api/` deliberately; `server.rs` explains what that prefix buys.
pub const DOWNLOAD_PATH: &str = "/api/auth_bundle";

/// A credential bundle, as it exists in the file.
///
/// JSON rather than a packed record: this is a file a person stores for months
/// and may have to eyeball, and every field but the two hex blobs exists for
/// exactly that reading. The blobs are hex rather than base64 for the same
/// reason the rest of this crate renders keys as hex — it is the form an
/// operator already copies between `--node-key` flags and dashboard fields.
#[cfg(feature = "ssr")]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthBundle {
    /// Layout version; see [`BUNDLE_VERSION`].
    pub version: u32,
    /// The account the certificate was issued to. A label for the header — the
    /// certificate does not carry a name, so nothing verifies this.
    pub username: String,
    /// What the certificate's signed flags mean, in words. Informational: the
    /// capability actually applied is recomputed from the certificate.
    pub capability: String,
    /// Unix seconds the certificate starts being valid. Informational.
    pub not_before: u64,
    /// Unix seconds the certificate stops being valid. Informational, and the
    /// value the filename carries.
    pub not_after: u64,
    /// The 32-byte Ed25519 session seed, hex. The secret half of the bundle.
    pub seed: String,
    /// The membership certificate the provider signed for that seed, hex.
    pub cert: String,
}

/// The credential a bundle carries once it has been checked over.
///
/// A separate type from [`AuthBundle`] so a caller cannot reach the seed
/// without having gone through [`AuthBundle::credential`] — the parsed file is
/// attacker-supplied text, and the validated credential is not.
#[cfg(feature = "ssr")]
pub struct BundleCredential {
    /// The session keypair's seed.
    pub seed: [u8; 32],
    /// The certificate, in the wire form the TLS handshake presents.
    pub cert: Vec<u8>,
    /// The parsed certificate, for the validity window and the capability bits.
    pub parsed: MembershipCert,
}

/// Written by hand, and the seed is not in it.
///
/// A derived `Debug` would put a private key into every `expect` message, every
/// `unwrap_err` in a test and anything that ever formats this with `{:?}` — and
/// the one thing this crate is careful about is where keys are allowed to
/// appear. The certificate is public by construction, so it is named by its
/// window rather than redacted.
#[cfg(feature = "ssr")]
impl std::fmt::Debug for BundleCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleCredential")
            .field("seed", &"<redacted>")
            .field("cert_len", &self.cert.len())
            .field("not_after", &self.parsed.not_after.get())
            .finish()
    }
}

#[cfg(feature = "ssr")]
impl AuthBundle {
    /// Build a bundle for a live session's credential.
    ///
    /// Errors when `cert` is not a certificate this build can parse, which
    /// would otherwise write a file that cannot be read back.
    pub fn issue(username: &str, seed: &[u8; 32], cert: &[u8]) -> anyhow::Result<Self> {
        let parsed = MembershipCert::from_bytes(cert)
            .context("this session's certificate cannot be parsed by this build")?;
        Ok(Self {
            version: BUNDLE_VERSION,
            username: username.to_string(),
            capability: capability(parsed.flags).to_string(),
            not_before: parsed.not_before.get(),
            not_after: parsed.not_after.get(),
            seed: to_hex(seed),
            cert: to_hex(cert),
        })
    }

    /// The file's contents.
    ///
    /// Pretty-printed with a trailing newline: it is a text file, and a text
    /// file without one is an annoyance in every tool that concatenates.
    pub fn encode(&self) -> String {
        // Infallible in practice — every field is a `String` or a `u64` — and
        // a bundle that cannot be serialised is a bug rather than a condition,
        // so it is reported as an empty-ish file rather than propagated
        // through a signature the caller would have to handle for nothing.
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Read a bundle out of a file's contents.
    ///
    /// Says which of the two failures it is — not a bundle at all, or a bundle
    /// this build is too old for — because the remedies are different and a
    /// single "invalid file" would point at neither.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let bundle: Self = serde_json::from_str(text.trim()).context(
            "this file is not a Wayfinder credential bundle (it is not the JSON one contains)",
        )?;
        if bundle.version != BUNDLE_VERSION {
            bail!(
                "this credential file is version {} and this dashboard reads version {}",
                bundle.version,
                BUNDLE_VERSION
            );
        }
        // The name is the one field with no certificate behind it, so it is
        // the one field an edited file can put anything at all into — and it
        // goes on to a log line, a download header and a page. Bounded here,
        // once, rather than defended against at each of those.
        if bundle.username.is_empty() || bundle.username.chars().count() > MAX_USERNAME_LEN {
            bail!("this credential file's account name is empty or implausibly long");
        }
        if bundle.username.chars().any(char::is_control) {
            bail!("this credential file's account name contains control characters");
        }
        Ok(bundle)
    }

    /// The credential inside, checked over as far as this side can check it.
    ///
    /// Three things are established here and one deliberately is not:
    ///
    /// * the seed and certificate are well-formed, and the certificate is a
    ///   version this build understands;
    /// * the certificate belongs to *this* seed, so a certificate lifted from
    ///   somebody else's bundle is refused rather than presented and denied;
    /// * the validity window contains `now_unix`, so an expired file is named
    ///   as expired instead of failing later as an unexplained refusal.
    ///
    /// What is **not** checked is the mesh root's signature, because this
    /// process holds no trust anchor to check it against — in login mode it
    /// holds no mesh identity at all. That is not a gap: the node verifies the
    /// signature at the handshake and refuses anything else, so a forged
    /// certificate buys a sign-in that cannot reach the node. The sign-in path
    /// closes the loop by asking the node before it calls the session real.
    pub fn credential(&self, now_unix: u64) -> anyhow::Result<BundleCredential> {
        let seed: [u8; 32] = from_hex(&self.seed)
            .context("the key in this credential file is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the key in this credential file must be 32 bytes"))?;
        let cert =
            from_hex(&self.cert).context("the certificate in this credential file is not hex")?;
        let parsed = MembershipCert::from_bytes(&cert)
            .context("the certificate in this credential file is truncated")?;

        if parsed.version != CERT_VERSION {
            bail!(
                "this credential's certificate is version {} and this build reads version \
                 {CERT_VERSION}",
                parsed.version
            );
        }
        if parsed.ed_pubkey != Keypair::from_seed(&seed).ed_pubkey() {
            bail!("this credential file's certificate does not belong to the key beside it");
        }
        let (not_before, not_after) = (parsed.not_before.get(), parsed.not_after.get());
        if now_unix >= not_after {
            bail!("this credential expired at {not_after} and a new one has to be downloaded");
        }
        if now_unix < not_before {
            bail!("this credential does not start being valid until {not_before}");
        }

        Ok(BundleCredential { seed, cert, parsed })
    }

    /// The name the browser saves this file under: `<user>-<expiry>.wfauth`.
    ///
    /// The expiry is in the name and not only in the file because that is the
    /// one fact a person needs while looking at a folder of these — a
    /// credential is worth nothing past it, and the alternative is opening
    /// each one to find out. UTC, stamped `YYYYMMDD-HHMM`: sortable, and free
    /// of the colons Windows refuses in a filename.
    pub fn filename(&self) -> String {
        format!(
            "{}-{}.{BUNDLE_EXTENSION}",
            safe_name(&self.username),
            crate::format::filename_stamp(self.not_after)
        )
    }
}

/// What a certificate's signed capability bits mean, in words a person reads.
///
/// Plain language rather than the flag names `wayfinderctl whoami` prints: this
/// is rendered into a page header and written into a file somebody opens in a
/// text editor, and "read-only" is the thing they need to know before they try
/// to change something. `CERT_FLAG_USER` is deliberately not named — every
/// certificate this reaches is a person's, so saying so adds a word and no
/// information.
#[cfg(feature = "ssr")]
pub fn capability(flags: u8) -> &'static str {
    if flags & wayfinder_auth::CERT_FLAG_ADMIN != 0 {
        "administrator"
    } else if flags & wayfinder_auth::CERT_FLAG_VIEWER != 0 {
        "read-only"
    } else {
        // Not reachable through a login — the provider issues one of the two
        // roles — but a certificate is a signed input and this is what it
        // would mean: a mesh membership with no management capability.
        "no management access"
    }
}

/// Whether a certificate's signed flags carry the administrator capability.
///
/// The same bit [`capability`] spells out, as the fact the dashboard branches
/// on. Kept beside it so the words and the behaviour are decided in one place:
/// a page that drew its controls by comparing [`capability`]'s string would
/// turn a wording change into a privilege change.
#[cfg(feature = "ssr")]
pub fn is_admin(flags: u8) -> bool {
    flags & wayfinder_auth::CERT_FLAG_ADMIN != 0
}

/// A user name reduced to what is safe in a filename on every platform.
///
/// A user name is an operator-chosen string that has never had to be one, so
/// anything outside a conservative set becomes `_` rather than reaching a
/// `Content-Disposition` header — where a quote or a newline is not a broken
/// filename but a header-injection primitive. An empty result becomes `user`,
/// since a name of `.wfauth` alone is a hidden file on Unix.
#[cfg(feature = "ssr")]
fn safe_name(username: &str) -> String {
    let cleaned: String = username
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '_']).to_string();
    if trimmed.is_empty() {
        "user".to_string()
    } else {
        trimmed
    }
}

/// Lowercase hex, the form every key in this crate is rendered in.
#[cfg(feature = "ssr")]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The inverse of [`to_hex`]: `None` for an odd length or a non-hex digit.
#[cfg(feature = "ssr")]
fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use wayfinder_auth::Authority;

    /// A certificate authority and the session certificate it issues, standing
    /// in for the provider a real bundle comes from.
    fn issued(admin: bool, window: (u64, u64)) -> (String, [u8; 32], Vec<u8>) {
        let authority = Authority::from_seed(&[0x33; 32], 0xBEEF);
        let seed = [0x77; 32];
        let keypair = Keypair::from_seed(&seed);
        let cert = authority.issue_user_cert(
            keypair.derived_mac(),
            keypair.ed_pubkey(),
            keypair.x_pubkey(),
            window.0,
            window.1,
            admin,
        );
        (
            "ops".to_string(),
            seed,
            zerocopy::IntoBytes::as_bytes(&cert).to_vec(),
        )
    }

    /// The round trip the whole feature rests on: what the download writes is
    /// what the sign-in reads, with the credential intact on the far side.
    #[test]
    fn a_bundle_survives_the_file_it_is_written_to() {
        let (username, seed, cert) = issued(true, (1_000, 9_000));

        let bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();
        let parsed = AuthBundle::parse(&bundle.encode()).unwrap();
        assert_eq!(parsed, bundle);

        let credential = parsed.credential(5_000).unwrap();
        assert_eq!(credential.seed, seed);
        assert_eq!(credential.cert, cert);
        assert_eq!(credential.parsed.not_after.get(), 9_000);
    }

    /// The human-facing fields are filled in from the certificate rather than
    /// from whatever the caller happened to have in a signal, so a file read
    /// months later says the same thing the header did.
    #[test]
    fn a_bundle_describes_the_certificate_it_carries() {
        let (username, seed, cert) = issued(false, (1_000, 9_000));

        let bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();

        assert_eq!(bundle.version, BUNDLE_VERSION);
        assert_eq!(bundle.username, "ops");
        assert_eq!(bundle.capability, "read-only");
        assert_eq!(bundle.not_before, 1_000);
        assert_eq!(bundle.not_after, 9_000);
        // The text is legible: a person opening this file finds the fields
        // named, not a wall of hex.
        assert!(bundle.encode().contains("\"capability\": \"read-only\""));
        assert!(bundle.encode().ends_with('\n'));
    }

    /// A certificate lifted from somebody else's bundle and pasted beside this
    /// one's key is refused here rather than presented to the node — the node
    /// would refuse it too, but a sign-in that fails as "the node did not
    /// accept this" points the reader at the wrong thing entirely.
    #[test]
    fn a_certificate_that_does_not_match_the_key_is_refused() {
        let (username, seed, cert) = issued(true, (1_000, 9_000));
        let mut bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();

        bundle.seed = to_hex(&[0x11; 32]);

        let error = bundle.credential(5_000).unwrap_err().to_string();
        assert!(error.contains("does not belong to the key"), "{error}");
    }

    /// An expired credential is named as expired. It is the failure this file
    /// format is *most* likely to hit — the whole point of it is being kept
    /// for a while — so it must not surface as an unexplained refusal from the
    /// node.
    #[test]
    fn an_expired_bundle_says_so_rather_than_being_offered_to_the_node() {
        let (username, seed, cert) = issued(true, (1_000, 9_000));
        let bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();

        let error = bundle.credential(9_000).unwrap_err().to_string();
        assert!(error.contains("expired"), "{error}");

        // And the other end of the window, which a clock skewed the other way
        // produces.
        let error = bundle.credential(999).unwrap_err().to_string();
        assert!(error.contains("does not start being valid"), "{error}");

        // The instant before expiry is still good: the boundary is `not_after`
        // exclusive, matching the certificate's own reading of it.
        assert!(bundle.credential(8_999).is_ok());
    }

    /// A file from a newer dashboard is refused by *version*, so the answer is
    /// "upgrade this dashboard" rather than "your file is corrupt".
    #[test]
    fn a_bundle_from_a_future_version_is_named_as_such() {
        let (username, seed, cert) = issued(true, (1_000, 9_000));
        let mut bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();
        bundle.version = BUNDLE_VERSION + 1;

        let error = AuthBundle::parse(&bundle.encode()).unwrap_err().to_string();
        assert!(error.contains("version"), "{error}");

        // And something that is not a bundle at all is a different answer.
        let error = AuthBundle::parse("not json at all")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not a Wayfinder credential bundle"),
            "{error}"
        );
    }

    /// The account name is the one field nothing signs, so it is the one an
    /// edited file can fill with anything — and it goes on to a log line, a
    /// download header and the page header. Bounded at the door.
    #[test]
    fn an_implausible_account_name_is_refused_at_the_door() {
        let (username, seed, cert) = issued(true, (1_000, 9_000));
        let good = AuthBundle::issue(&username, &seed, &cert).unwrap();

        for (label, name) in [
            ("empty", String::new()),
            ("unbounded", "a".repeat(MAX_USERNAME_LEN + 1)),
            ("a log-line break", "ops\nlevel=INFO".to_string()),
            ("a header break", "ops\r\nSet-Cookie: x=1".to_string()),
        ] {
            let mut bundle = good.clone();
            bundle.username = name;
            assert!(
                AuthBundle::parse(&bundle.encode()).is_err(),
                "an account name that is {label} is refused"
            );
        }

        // And the boundary itself is admitted: this is a guard, not a policy.
        let mut bundle = good.clone();
        bundle.username = "a".repeat(MAX_USERNAME_LEN);
        assert!(AuthBundle::parse(&bundle.encode()).is_ok());
    }

    /// The filename carries who and until when, because a folder of these is
    /// otherwise unreadable.
    #[test]
    fn the_filename_names_the_account_and_the_expiry() {
        let (username, seed, cert) = issued(true, (1_700_000_000, 1_700_086_400));
        let bundle = AuthBundle::issue(&username, &seed, &cert).unwrap();

        assert_eq!(bundle.filename(), "ops-20231115-2213.wfauth");
    }

    /// A user name is an operator-chosen string that has never had to be a
    /// filename. Anything outside a conservative set becomes `_` — in a
    /// `Content-Disposition` header a quote is not a broken name, it is a way
    /// to write a second header field.
    #[test]
    fn a_hostile_user_name_cannot_reach_the_download_header() {
        for (name, expected) in [
            ("ops", "ops"),
            ("field.op_2", "field.op_2"),
            ("a/b", "a_b"),
            ("\"; attachment; filename=\"x", "attachment__filename__x"),
            ("../../etc/passwd", "etc_passwd"),
            ("...", "user"),
            ("", "user"),
        ] {
            assert_eq!(safe_name(name), expected, "{name:?}");
        }
    }

    /// Hex is the only encoding here, so its edges are worth pinning: an odd
    /// length and a stray character are both rejections rather than a silently
    /// truncated key.
    #[test]
    fn hex_round_trips_and_rejects_what_is_not_hex() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(from_hex("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert_eq!(from_hex("00f"), None, "an odd length is not a byte string");
        assert_eq!(from_hex("00zz"), None);
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }
}
