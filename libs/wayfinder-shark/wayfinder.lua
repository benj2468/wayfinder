-- Wireshark/tshark dissector for the Wayfinder mesh wire format.
--
-- A Wayfinder LinkFrame is byte-identical to an Ethernet frame
-- ([dst][src][ethertype][payload]), so Wireshark's built-in `eth` dissector
-- parses the dst/src/type for us. We register on the `ethertype` table and
-- dissect the BATMAN body that `eth` hands us.
--
-- Two EtherTypes reach a capture, because a raw-L2 carrier separates the wire
-- *transport label* from the *mesh protocol* (libs/wayfinder-driver/src/raw.rs).
-- Both are claimed, so a capture decodes whichever the deployment produced:
--
--   * 0x4305 (ETH_P_BATMAN) — the mesh protocol a LinkFrame's `protocol` field
--     carries, and what a carrier with no wire/mesh split (TAP, UDP) puts on
--     the wire. Always registered; it identifies the protocol itself.
--   * the *carrier* EtherType — what an AF_PACKET raw-L2 socket or the nRF's
--     CDC-NCM USB link actually stamps, so co-located meshes stay apart. The
--     receiver retags it back to 0x4305 in place, so only a capture ever sees
--     it. 0xfafa is this repo's default (`MESH_ETHERTYPE` in
--     libs/wayfinder-nrf/src/usb_link.rs, `ethertype:` in containers/node.yml),
--     but it is a per-deployment choice — override it with the
--     `wayfinder.carrier_ethertype` preference when yours differs:
--       tshark -o wayfinder.carrier_ethertype:0x88b5 ...
--     Set it empty to claim only 0x4305.
--
-- Decodes the BatmanOgmPacket fixed header (see libs/batman/src/wire.rs) and
-- walks the TVLV tail into individual records: multicast membership, the
-- Wayfinder membership certificate (WF_TVLV_CERT), the originator signature
-- (WF_TVLV_ORIGINATOR_SIG), flooded revocations (WF_TVLV_REVOKE), and the
-- lazy-cert-distribution fingerprint (WF_TVLV_CERTFP) that replaces
-- WF_TVLV_CERT on the wire once fingerprinting is enabled.  The whole tail is
-- also shown as a raw byte blob.  Also decodes the lazy-cert-distribution
-- control packets (BatmanPacketType::CertReq / CertReply): their shared
-- header plus the requester's cert + signature, or the replied cert.
--
-- Install one of two ways — not both, or the second load fails with "there
-- cannot be two protocols with the same description" (non-fatal: the first copy
-- still dissects, but the error is noise):
--
--   * Persistently, by symlinking this file into your Personal Lua Plugins
--     folder — `tshark -G folders` prints its path, and Wireshark also scans a
--     per-version subdirectory under it:
--       ln -s "$PWD/wayfinder.lua" ~/.local/lib/wireshark/plugins/4.6/
--   * Ad hoc, for a one-off capture:  tshark -X lua_script:wayfinder.lua ...
--
-- Capturing live needs CAP_NET_RAW on `dumpcap`, which a read-only Nix store
-- can't be granted with `setcap`; on NixOS set `programs.wireshark.enable =
-- true` (installs a setcap wrapper and a `wireshark` group to join). Reading a
-- pcap needs no privilege at all.

-- The mesh protocol itself (libs/batman/src/wire.rs's ETH_P_BATMAN).
local ETH_P_BATMAN = 0x4305

-- Default wire transport label for the raw-L2 / CDC-NCM carriers; overridable
-- via the `wayfinder.carrier_ethertype` preference. See the module header.
local DEFAULT_CARRIER_ETHERTYPE = 0xfafa

-- BATMAN packet_type byte values (libs/batman/src/wire.rs's BatmanPacketType).
local PKT_ORIGINATOR = 0x01
local PKT_CERT_REQ = 0x05
local PKT_CERT_REPLY = 0x06
local PACKET_TYPES = {
	[PKT_ORIGINATOR] = "Originator",
	[0x02] = "Broadcast",
	[0x03] = "Unicast",
	[0x04] = "Multicast",
	[PKT_CERT_REQ] = "Cert Request",
	[PKT_CERT_REPLY] = "Cert Reply",
}

-- TVLV record type bytes carried in an Originator packet's tail (libs/batman/src/wire.rs).
local BATADV_TVLV_MCAST = 0x06
local WF_TVLV_CERT = 0x80
local WF_TVLV_ORIGINATOR_SIG = 0x81
local WF_TVLV_REVOKE = 0x82
local WF_TVLV_CERTFP = 0x83
local TVLV_TYPES = {
	[BATADV_TVLV_MCAST] = "Multicast Membership",
	[WF_TVLV_CERT] = "Membership Certificate",
	[WF_TVLV_ORIGINATOR_SIG] = "Originator Signature",
	[WF_TVLV_REVOKE] = "Revocation",
	[WF_TVLV_CERTFP] = "Cert Fingerprint",
}

-- Length of the Ed25519 signature following a CertReq's requester cert (see
-- SIG_LEN in libs/wayfinder/src/auth.rs).
local SIG_LEN = 64

local wayfinder = Proto("wayfinder", "Wayfinder Mesh Protocol")

-- Header fields. Filter names describe what each field does rather than the
-- BATMAN wire terminology — e.g. `wayfinder.originator.seqno`, not
-- `wayfinder.batman.ogm.seqno` — even though the underlying Rust struct is
-- still `BatmanOgmPacket` (libs/batman/src/wire.rs). Outward-facing BATMAN
-- references are being phased out incrementally.
local f = wayfinder.fields
f.packet_type = ProtoField.uint8("wayfinder.type", "Packet Type", base.HEX, PACKET_TYPES)
f.version = ProtoField.uint8("wayfinder.version", "Version", base.DEC)
f.ttl = ProtoField.uint8("wayfinder.ttl", "TTL", base.DEC)
f.flags = ProtoField.uint8("wayfinder.originator.flags", "Flags", base.HEX)
f.seqno = ProtoField.uint32("wayfinder.originator.seqno", "Sequence Number", base.DEC)
f.orig = ProtoField.ether("wayfinder.originator.addr", "Originator Address")
f.reserved = ProtoField.uint8("wayfinder.originator.reserved", "Reserved", base.HEX)
f.tq = ProtoField.uint8("wayfinder.originator.tq", "Transmission Quality", base.DEC)
f.tvlv_len = ProtoField.uint16("wayfinder.originator.tvlv_len", "TVLV Length", base.DEC)
f.tvlv = ProtoField.bytes("wayfinder.originator.tvlv", "TVLV Data")

-- Per-record TVLV fields (the tail walked into individual records).
f.tvlv_record = ProtoField.bytes("wayfinder.tvlv.record", "TVLV Record")
f.tvlv_type = ProtoField.uint8("wayfinder.tvlv.type", "TVLV Type", base.HEX, TVLV_TYPES)
f.tvlv_ver = ProtoField.uint8("wayfinder.tvlv.version", "TVLV Version", base.DEC)
f.tvlv_vlen = ProtoField.uint16("wayfinder.tvlv.len", "TVLV Value Length", base.DEC)
f.tvlv_value = ProtoField.bytes("wayfinder.tvlv.value", "TVLV Value")

-- Multicast membership announcement: a back-to-back list of group MACs.
f.mcast_group = ProtoField.ether("wayfinder.tvlv.mcast_group", "Multicast Group")

-- Membership certificate fields (wayfinder_auth::MembershipCert; see
-- libs/wayfinder-auth/src/cert.rs).
f.cert_version = ProtoField.uint8("wayfinder.tvlv.cert.version", "Cert Version", base.DEC)
f.cert_mesh = ProtoField.uint32("wayfinder.tvlv.cert.mesh_id", "Mesh ID", base.HEX)
f.cert_mac = ProtoField.ether("wayfinder.tvlv.cert.node_mac", "Node MAC")
f.cert_ed = ProtoField.bytes("wayfinder.tvlv.cert.ed_pubkey", "Ed25519 Public Key")
f.cert_x = ProtoField.bytes("wayfinder.tvlv.cert.x_pubkey", "X25519 Public Key")
f.cert_nb = ProtoField.uint64("wayfinder.tvlv.cert.not_before", "Not Before", base.DEC)
f.cert_na = ProtoField.uint64("wayfinder.tvlv.cert.not_after", "Not After", base.DEC)
f.cert_sig = ProtoField.bytes("wayfinder.tvlv.cert.signature", "Root Signature")

-- The originator's Ed25519 signature over the packet's immutable identity.
f.originator_sig = ProtoField.bytes("wayfinder.tvlv.originator_sig", "Originator Signature")

-- Lazy-cert-distribution fingerprint: MembershipCert::fingerprint(), replacing
-- the full WF_TVLV_CERT record on the wire once fingerprinting is enabled
-- (libs/batman/src/wire.rs).
f.cert_fp = ProtoField.bytes("wayfinder.tvlv.cert_fp", "Cert Fingerprint")

-- Shared header fields for the cert-control packets (BatmanPacketType::CertReq
-- / CertReply): structurally a unicast header (version/ttl/dest).
f.cert_ctrl_version = ProtoField.uint8("wayfinder.cert_ctrl.version", "Version", base.DEC)
f.cert_ctrl_ttl = ProtoField.uint8("wayfinder.cert_ctrl.ttl", "TTL", base.DEC)
f.cert_ctrl_dest = ProtoField.ether("wayfinder.cert_ctrl.dest", "Destination")

-- The requester's self-authenticating Ed25519 signature following its cert in
-- a BatmanPacketType::CertReq body (see OgmAuth::build_cert_request in
-- libs/wayfinder/src/auth.rs).
f.cert_req_sig = ProtoField.bytes("wayfinder.cert_req.signature", "Requester Signature")

-- Revocation record fields (wayfinder_auth::RevocationRecord; see
-- libs/wayfinder-auth/src/revoke.rs).
f.revoke_version = ProtoField.uint8("wayfinder.tvlv.revoke.version", "Revoke Version", base.DEC)
f.revoke_flags = ProtoField.uint8("wayfinder.tvlv.revoke.flags", "Flags", base.HEX)
f.revoke_mesh = ProtoField.uint32("wayfinder.tvlv.revoke.mesh_id", "Mesh ID", base.HEX)
f.revoke_mac = ProtoField.ether("wayfinder.tvlv.revoke.node_mac", "Revoked Node MAC")
f.revoke_nb = ProtoField.uint64("wayfinder.tvlv.revoke.not_before", "Not Before", base.DEC)
f.revoke_na = ProtoField.uint64("wayfinder.tvlv.revoke.not_after", "Not After", base.DEC)
f.revoke_sig = ProtoField.bytes("wayfinder.tvlv.revoke.signature", "Root Signature")

-- Offsets of the fixed BatmanOgmPacket fields (the wire form of an Originator
-- packet) within the BATMAN body. Kept in sync with libs/batman/src/wire.rs.
local ORIGINATOR = {
	PACKET_TYPE = 0,
	VERSION = 1,
	TTL = 2,
	FLAGS = 3,
	SEQNO = 4, -- u32, big-endian
	ORIG = 8, -- 6 bytes
	RESERVED = 14,
	TQ = 15,
	TVLV_LEN = 16, -- u16, big-endian
	HEADER_LEN = 18,
}

-- Field offsets within a BatmanCertReqPacket / BatmanCertReplyPacket header —
-- structurally identical (type/version/ttl/dest). Kept in sync with
-- libs/batman/src/wire.rs.
local CERT_CTRL = {
	PACKET_TYPE = 0,
	VERSION = 1,
	TTL = 2,
	DEST = 3, -- 6 bytes
	HEADER_LEN = 9,
}

-- Field offsets within a MembershipCert value (libs/wayfinder-auth/src/cert.rs).
local CERT = {
	VERSION = 0,
	FLAGS = 1,
	MESH_ID = 2, -- u32, big-endian
	NODE_MAC = 6, -- 6 bytes
	ED_PUBKEY = 12, -- 32 bytes
	X_PUBKEY = 44, -- 32 bytes
	NOT_BEFORE = 76, -- u64, big-endian
	NOT_AFTER = 84, -- u64, big-endian
	SIGNATURE = 92, -- 64 bytes
	LEN = 156,
}

-- Field offsets within a RevocationRecord value (libs/wayfinder-auth/src/revoke.rs).
local REVOKE = {
	VERSION = 0,
	FLAGS = 1,
	MESH_ID = 2, -- u32, big-endian
	NODE_MAC = 6, -- 6 bytes
	NOT_BEFORE = 12, -- u64, big-endian
	NOT_AFTER = 20, -- u64, big-endian
	SIGNATURE = 28, -- 64 bytes
	LEN = 92,
}

-- Decode one membership-certificate TVLV value into `rec` (the record subtree).
local function decode_cert(rec, tvb, voff, vlen, cap_end)
	if voff + CERT.LEN > cap_end or vlen < CERT.LEN then
		return -- truncated capture or short value; leave as raw value below
	end
	rec:add(f.cert_version, tvb(voff + CERT.VERSION, 1))
	rec:add(f.cert_mesh, tvb(voff + CERT.MESH_ID, 4))
	rec:add(f.cert_mac, tvb(voff + CERT.NODE_MAC, 6))
	rec:add(f.cert_ed, tvb(voff + CERT.ED_PUBKEY, 32))
	rec:add(f.cert_x, tvb(voff + CERT.X_PUBKEY, 32))
	rec:add(f.cert_nb, tvb(voff + CERT.NOT_BEFORE, 8))
	rec:add(f.cert_na, tvb(voff + CERT.NOT_AFTER, 8))
	rec:add(f.cert_sig, tvb(voff + CERT.SIGNATURE, 64))
end

-- Decode one revocation-record TVLV value into `rec` (the record subtree).
local function decode_revoke(rec, tvb, voff, vlen, cap_end)
	if voff + REVOKE.LEN > cap_end or vlen < REVOKE.LEN then
		return -- truncated capture or short value; leave as raw value below
	end
	rec:add(f.revoke_version, tvb(voff + REVOKE.VERSION, 1))
	rec:add(f.revoke_flags, tvb(voff + REVOKE.FLAGS, 1))
	rec:add(f.revoke_mesh, tvb(voff + REVOKE.MESH_ID, 4))
	rec:add(f.revoke_mac, tvb(voff + REVOKE.NODE_MAC, 6))
	rec:add(f.revoke_nb, tvb(voff + REVOKE.NOT_BEFORE, 8))
	rec:add(f.revoke_na, tvb(voff + REVOKE.NOT_AFTER, 8))
	rec:add(f.revoke_sig, tvb(voff + REVOKE.SIGNATURE, 64))
end

-- Decode a CertReq / CertReply body into `tree`: the shared
-- header (version/ttl/dest) is already consumed by the caller, so `tvb`
-- starts at the body — the requester's own cert + a self-authenticating
-- signature for a request, or the requested originator's raw cert for a
-- reply. Degrades gracefully (leaves the body undissected) on a truncated
-- capture, matching `walk_tvlv`'s bounds handling.
local function decode_cert_ctrl(tree, tvb, is_req, body_off, cap_end)
	if body_off + CERT.LEN > cap_end then
		return
	end
	local cert_tree = tree:add(tvb(body_off, CERT.LEN), is_req and "Requester Certificate" or "Certificate")
	decode_cert(cert_tree, tvb, body_off, CERT.LEN, cap_end)

	if is_req then
		local sig_off = body_off + CERT.LEN
		if sig_off + SIG_LEN <= cap_end then
			tree:add(f.cert_req_sig, tvb(sig_off, SIG_LEN))
		end
	end
end

-- Walk the TVLV tail into one subtree per record, decoding known types. Bounds
-- are clamped to `cap_end` (what the capture actually holds) so a truncated or
-- malformed tail degrades gracefully rather than erroring.
local function walk_tvlv(tree, tvb, start, tvlv_len, cap_end)
	local records = tree:add(tvb(start, math.min(start + tvlv_len, cap_end) - start), "TVLV Records")
	local off = start
	local tail_end = start + tvlv_len
	while off + 4 <= tail_end and off + 4 <= cap_end do
		local ttype = tvb(off, 1):uint()
		local vlen = tvb(off + 2, 2):uint()
		local voff = off + 4
		local rec_end = voff + vlen
		local shown_end = math.min(rec_end, cap_end)
		local rec = records:add(f.tvlv_record, tvb(off, shown_end - off))
		rec:append_text(string.format(" (%s)", TVLV_TYPES[ttype] or string.format("0x%02x", ttype)))
		rec:add(f.tvlv_type, tvb(off, 1))
		rec:add(f.tvlv_ver, tvb(off + 1, 1))
		rec:add(f.tvlv_vlen, tvb(off + 2, 2))

		if voff + vlen <= cap_end then
			if ttype == WF_TVLV_CERT then
				decode_cert(rec, tvb, voff, vlen, cap_end)
			elseif ttype == WF_TVLV_ORIGINATOR_SIG then
				rec:add(f.originator_sig, tvb(voff, vlen))
			elseif ttype == WF_TVLV_REVOKE then
				decode_revoke(rec, tvb, voff, vlen, cap_end)
			elseif ttype == WF_TVLV_CERTFP then
				rec:add(f.cert_fp, tvb(voff, vlen))
			elseif ttype == BATADV_TVLV_MCAST then
				local g = voff
				while g + 6 <= voff + vlen do
					rec:add(f.mcast_group, tvb(g, 6))
					g = g + 6
				end
			else
				rec:add(f.tvlv_value, tvb(voff, vlen))
			end
		end

		if vlen == 0 and ttype == 0 then
			break -- avoid spinning on a zero-filled tail
		end
		off = rec_end
	end
end

function wayfinder.dissector(tvb, pinfo, root)
	local len = tvb:len()
	if len < 1 then
		return 0
	end

	pinfo.cols.protocol = "Wayfinder"

	local ptype = tvb(ORIGINATOR.PACKET_TYPE, 1):uint()
	local label = PACKET_TYPES[ptype]
	pinfo.cols.info = label or string.format("(unknown type 0x%02x)", ptype)

	local tree = root:add(wayfinder, tvb(), "Wayfinder Mesh Protocol")
	tree:add(f.packet_type, tvb(ORIGINATOR.PACKET_TYPE, 1))

	-- Cert-control packets (CertReq/CertReply) get their own header/body
	-- decode; Broadcast/Unicast/Multicast stop after the protocol/type are
	-- labelled (not decoded in this cut).
	if ptype == PKT_CERT_REQ or ptype == PKT_CERT_REPLY then
		if len < CERT_CTRL.HEADER_LEN then
			return len
		end
		tree:add(f.cert_ctrl_version, tvb(CERT_CTRL.VERSION, 1))
		tree:add(f.cert_ctrl_ttl, tvb(CERT_CTRL.TTL, 1))
		tree:add(f.cert_ctrl_dest, tvb(CERT_CTRL.DEST, 6))
		decode_cert_ctrl(tree, tvb, ptype == PKT_CERT_REQ, CERT_CTRL.HEADER_LEN, len)
		return len
	end

	if ptype ~= PKT_ORIGINATOR or len < ORIGINATOR.HEADER_LEN then
		return len
	end

	tree:add(f.version, tvb(ORIGINATOR.VERSION, 1))
	tree:add(f.ttl, tvb(ORIGINATOR.TTL, 1))
	tree:add(f.flags, tvb(ORIGINATOR.FLAGS, 1))
	tree:add(f.seqno, tvb(ORIGINATOR.SEQNO, 4))
	tree:add(f.orig, tvb(ORIGINATOR.ORIG, 6))
	tree:add(f.reserved, tvb(ORIGINATOR.RESERVED, 1))
	tree:add(f.tq, tvb(ORIGINATOR.TQ, 1))
	tree:add(f.tvlv_len, tvb(ORIGINATOR.TVLV_LEN, 2))

	-- The TVLV tail (tvlv_len bytes) follows the fixed header. Show it raw, then
	-- also walk it into individual records (cert / signature / multicast),
	-- clamped to what the capture actually holds.
	local tvlv_len = tvb(ORIGINATOR.TVLV_LEN, 2):uint()
	if tvlv_len > 0 then
		local avail = len - ORIGINATOR.HEADER_LEN
		local take = math.min(tvlv_len, avail)
		if take > 0 then
			tree:add(f.tvlv, tvb(ORIGINATOR.HEADER_LEN, take))
			walk_tvlv(tree, tvb, ORIGINATOR.HEADER_LEN, tvlv_len, len)
		end
	end

	return len
end

-- Registration. The mesh protocol is claimed unconditionally; the configurable
-- carrier label is claimed on top of it, and re-claimed whenever the preference
-- changes.
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(ETH_P_BATMAN, wayfinder)

-- The carrier EtherType currently registered, so a preference change can
-- release it. Removing the stale entry is the half that's easy to forget: the
-- dissector table is global state, so an add-only update would keep decoding an
-- EtherType the operator has configured away.
local registered_carrier = nil

-- Apply `wayfinder.carrier_ethertype` to the dissector table.
--
-- The preference is a *string* rather than a `Pref.uint` so it accepts the hex
-- spelling every other config in this repo uses (`Pref.uint` only takes
-- decimal via `-o`, e.g. "0xfafa" itself would reject rather than parse).
-- `tonumber` takes both spellings.
--
-- An empty value registers nothing extra, by design (see the pref's own help
-- text). Anything non-empty that doesn't parse, is out of range, or collides
-- with the mesh protocol itself is a misconfiguration, not "disabled" — warn
-- so it isn't mistaken for the empty case.
local function apply_carrier_pref()
	local raw = wayfinder.prefs.carrier_ethertype
	local wanted = tonumber(raw)
	if raw ~= "" and (not wanted or wanted <= 0 or wanted > 0xffff or wanted == ETH_P_BATMAN) then
		report_failure("wayfinder: ignoring invalid carrier_ethertype '" .. raw .. "'")
		wanted = nil
	end
	if wanted == registered_carrier then
		return
	end
	if registered_carrier then
		ethertype_table:remove(registered_carrier, wayfinder)
	end
	if wanted then
		ethertype_table:add(wanted, wayfinder)
	end
	registered_carrier = wanted
end

wayfinder.prefs.carrier_ethertype = Pref.string(
	"Carrier EtherType",
	string.format("0x%04x", DEFAULT_CARRIER_ETHERTYPE),
	"EtherType the raw-L2 / USB carrier stamps on the wire, decimal or 0x-hex. "
		.. "Empty to decode only the mesh protocol (0x4305)."
)

-- Wireshark calls this after preferences are read (including `-o`), and again
-- on every later change.
function wayfinder.prefs_changed()
	apply_carrier_pref()
end

apply_carrier_pref()
