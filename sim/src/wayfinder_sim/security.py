"""Mesh identity for the simulation: a root of trust, and the credentials
nodes present to it — including the ones that are deliberately wrong.

A `Simulation` given a `Mesh` runs an *authenticated* mesh: every node
carrying a `Credential` is enrolled against that mesh's root before the run
starts, and the router signs the OGMs it emits and rejects the ones that do
not verify. Without a `Mesh` the simulation is open and unauthenticated,
which is what every pre-existing scenario expects.

The `Credential` fields exist mostly so a red-team scenario can get them
wrong on purpose. Each corresponds to one way a real node fails to belong:

* `mesh=<another Mesh>` — a valid certificate signed by a *foreign* root.
  Every field checks out and the signature still fails, which is the whole
  of what segregates one mesh from another.
* `valid_until_s` — a certificate that expires mid-run. Expiry is the
  *passive* revocation mechanism, and the only one that works with no
  network at all.
* `enrolled=False` — required to authenticate, holding nothing. The
  fail-closed state: inert on the mesh rather than falling back to open.
* `claim_mac` — a certificate naming a MAC the key does not derive. The
  router accepts it, because certificate verification checks the root's
  signature and not the key-to-MAC derivation: an authority that will sign
  such a certificate hands out impersonation. This models CA *misissuance*,
  not a break in the router.

**Scope.** Wayfinder authenticates and segregates; it never encrypts. No
credential here buys confidentiality, and `adversary.Wiretap` exists partly
to keep that honest.
"""

from __future__ import annotations

import dataclasses
import hashlib

import wayfinder_py as wf

DEFAULT_MESH_ID = 0x5741_5946
"""Default mesh id ("WAYF" in ASCII) — a label distinguishing meshes in
logs and on the wire, *not* a security boundary. The root key is the
boundary; two meshes sharing an id but not a root cannot route to each
other."""

DEFAULT_EPOCH_UNIX = 1_700_000_000
"""Wall-clock unix second that simulation time zero maps onto.

Certificate validity is judged in unix seconds while the tick driver counts
monotonic milliseconds from zero, so something has to bridge the two. The
exact value is arbitrary; that it is fixed is what makes a run
reproducible."""

DEFAULT_CERT_LIFETIME_S = 86_400.0
"""How long an enrolled node's certificate lasts by default, in simulation
seconds. Long enough that expiry never surprises a scenario that isn't
studying it — a scenario that *is* sets `Credential.valid_until_s`."""

_KEY_DERIVE_LABEL = b"wayfinder-sim-node-seed-v1"


@dataclasses.dataclass(frozen=True)
class Credential:
    """What a node presents to the mesh.

    The default — `Credential()` — is an ordinary member in good standing:
    enrolled against the simulation's own mesh, valid for the whole run, with
    a MAC derived from its own key.
    """

    mesh: Mesh | None = None
    """Which root signs this credential. `None` means the simulation's own
    mesh; any other `Mesh` makes this node a foreign-mesh intruder."""

    enrolled: bool = True
    """Whether a certificate is actually installed. `False` leaves the node
    requiring authentication with nothing to authenticate *with* — the
    fail-closed, inert state."""

    valid_from_s: float = 0.0
    """When this certificate becomes valid, in simulation seconds. Negative
    values are fine (and are the norm — a node's credentials predate the
    run)."""

    valid_until_s: float | None = None
    """When this certificate expires, in simulation seconds; `None` means
    `DEFAULT_CERT_LIFETIME_S` after the run starts. Set it to model a node
    whose enrollment lapses mid-run."""

    seed: bytes | None = None
    """The 32-byte identity seed. `None` derives one from the mesh root and
    the node's name, so identities are reproducible without a scenario
    inventing key material."""

    claim_mac: wf.PyMac | None = None
    """The MAC this certificate claims. `None` — correct, and the only
    honest option — uses the MAC the key derives. Setting it mints a
    certificate binding a key to an address it does not own, which is what
    an impersonation attempt needs a misissuing authority to hand it."""

    require_auth: bool = True
    """Fail closed when no certificate is installed. Only observable when
    `enrolled` is `False`; an enrolled node is never locked."""


class Mesh:
    """A mesh's root of trust, and the certificate authority that speaks for
    it.

    One `Mesh` *is* one mesh. A scenario wanting an intruder with
    valid-looking papers builds a second `Mesh` and enrolls the intruder
    against that.
    """

    def __init__(
        self,
        *,
        mesh_id: int = DEFAULT_MESH_ID,
        root_seed: bytes | None = None,
        epoch_unix: int = DEFAULT_EPOCH_UNIX,
    ) -> None:
        """`root_seed` is the 32-byte mesh root key — the entire root of
        trust. `None` draws one from the OS RNG, which is realistic but makes
        the run unreproducible; a scenario should pass a fixed seed.
        `epoch_unix` is the wall-clock second simulation time zero maps to.
        """
        if root_seed is None:
            self._authority = wf.PyAuthority.generate(mesh_id)
        else:
            self._authority = wf.PyAuthority.from_seed(root_seed, mesh_id)
        self._root_seed = root_seed
        self._epoch_unix = epoch_unix

    @property
    def mesh_id(self) -> int:
        """The id this mesh labels itself with on the wire."""
        return self._authority.mesh_id

    @property
    def epoch_unix(self) -> int:
        """The wall-clock second simulation time zero corresponds to."""
        return self._epoch_unix

    @property
    def trust_anchor(self) -> wf.PyTrustAnchor:
        """The public anchor every member verifies certificates against."""
        return self._authority.trust_anchor()

    def keypair(self, name: str, seed: bytes | None = None) -> wf.PyKeypair:
        """This mesh's identity for the node called `name`.

        Derived from the mesh root seed and the name, so the same scenario
        always produces the same MACs — which matters when a recorded run is
        compared against another. Pass `seed` to supply key material
        directly instead.
        """
        if seed is not None:
            return wf.PyKeypair.from_seed(seed)
        digest = hashlib.blake2s(
            name.encode(), key=self._name_key(), person=b"wfsim-id"
        ).digest()
        return wf.PyKeypair.from_seed(digest)

    def _name_key(self) -> bytes:
        """Keying material for per-name identity derivation.

        Uses the mesh root seed when there is one, so two meshes never derive
        the same node identity. A generated (seedless) root has none to reach,
        so it falls back to the anchor's public key — different per mesh, and
        public, which is fine: these seeds are simulation identities, not
        secrets.
        """
        if self._root_seed is not None:
            return self._root_seed
        return bytes(self.trust_anchor.root_pubkey)

    def enroll(
        self,
        keypair: wf.PyKeypair,
        *,
        valid_from_s: float = 0.0,
        valid_until_s: float | None = None,
        claim_mac: wf.PyMac | None = None,
    ) -> wf.PyMembershipCert:
        """Issue a membership certificate for `keypair`, with the validity
        window given in *simulation* seconds (mapped onto the unix clock via
        `epoch_unix`).

        `claim_mac` overrides the key-derived MAC — a misissuance, and the
        only way to mint a credential for an address its holder cannot prove
        it owns.
        """
        if valid_until_s is None:
            valid_until_s = DEFAULT_CERT_LIFETIME_S
        not_before = self._epoch_unix + int(valid_from_s)
        not_after = self._epoch_unix + int(valid_until_s)
        if claim_mac is None:
            return self._authority.enroll(keypair, not_before, not_after)
        return self._authority.issue_cert(
            claim_mac,
            keypair.ed_pubkey,
            keypair.x_pubkey,
            not_before,
            not_after,
        )

    def revoke(
        self,
        mac: wf.PyMac,
        *,
        effective_s: float = 0.0,
        until_s: float | None = None,
    ) -> wf.PyRevocationRecord:
        """Sign a revocation purging `mac`.

        `until_s` must reach at least the revoked certificate's own expiry, or
        members may forget the record while the certificate it cancels is
        still valid — so it defaults to the same lifetime enrollment uses.
        """
        if until_s is None:
            until_s = DEFAULT_CERT_LIFETIME_S
        return self._authority.revoke(
            mac,
            self._epoch_unix + int(effective_s),
            self._epoch_unix + int(until_s),
        )

    def __repr__(self) -> str:
        return f"Mesh(mesh_id=0x{self.mesh_id:08x})"
