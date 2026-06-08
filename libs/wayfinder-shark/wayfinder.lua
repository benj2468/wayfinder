-- Wireshark/tshark dissector for the Wayfinder mesh wire format.
--
-- A Wayfinder LinkFrame is byte-identical to an Ethernet frame
-- ([dst][src][ethertype][payload]), so Wireshark's built-in `eth` dissector
-- parses the dst/src/type for us. We register on the `ethertype` table for
-- 0x4305 (ETH_P_BATMAN) and dissect the BATMAN body that `eth` hands us.
--
-- This first cut decodes the BatmanOgmPacket fixed header (see
-- libs/batman/src/wire.rs); the TVLV tail is shown as raw bytes.
--
-- Install: copy (or symlink) this file into your Personal Lua Plugins folder
--   (Help -> About -> Folders, e.g. ~/.local/lib/wireshark/plugins), or load it
--   ad hoc with:  tshark -X lua_script:wayfinder.lua ...

local ETH_P_BATMAN = 0x4305

-- BATMAN packet_type byte values (libs/batman/src/wire.rs).
local BATADV_IV_OGM = 0x01
local PACKET_TYPES = {
	[0x01] = "OGM",
	[0x02] = "Broadcast",
	[0x03] = "Unicast",
	[0x04] = "Multicast",
}

local wayfinder = Proto("wayfinder", "Wayfinder Mesh Protocol")

-- Header fields. Abbrevs mirror the Rust field names so display filters read
-- the same as the wire struct (e.g. `wayfinder.batman.ogm.seqno`).
local f = wayfinder.fields
f.packet_type = ProtoField.uint8("wayfinder.batman.type", "Packet Type", base.HEX, PACKET_TYPES)
f.version = ProtoField.uint8("wayfinder.batman.version", "Version", base.DEC)
f.ttl = ProtoField.uint8("wayfinder.batman.ttl", "TTL", base.DEC)
f.flags = ProtoField.uint8("wayfinder.batman.ogm.flags", "Flags", base.HEX)
f.seqno = ProtoField.uint32("wayfinder.batman.ogm.seqno", "Sequence Number", base.DEC)
f.orig = ProtoField.ether("wayfinder.batman.ogm.orig", "Originator")
f.prev_sender = ProtoField.ether("wayfinder.batman.ogm.prev_sender", "Previous Sender")
f.reserved = ProtoField.uint8("wayfinder.batman.ogm.reserved", "Reserved", base.HEX)
f.tq = ProtoField.uint8("wayfinder.batman.ogm.tq", "Transmission Quality", base.DEC)
f.tvlv_len = ProtoField.uint16("wayfinder.batman.ogm.tvlv_len", "TVLV Length", base.DEC)
f.tvlv = ProtoField.bytes("wayfinder.batman.ogm.tvlv", "TVLV Data")

-- Offsets of the fixed BatmanOgmPacket fields within the BATMAN body. Kept in
-- sync with libs/batman/src/wire.rs.
local OGM = {
	PACKET_TYPE = 0,
	VERSION = 1,
	TTL = 2,
	FLAGS = 3,
	SEQNO = 4, -- u32, big-endian
	ORIG = 8, -- 6 bytes
	PREV_SENDER = 14, -- 6 bytes
	RESERVED = 20,
	TQ = 21,
	TVLV_LEN = 22, -- u16, big-endian
	HEADER_LEN = 24,
}

function wayfinder.dissector(tvb, pinfo, root)
	local len = tvb:len()
	if len < 1 then
		return 0
	end

	pinfo.cols.protocol = "Wayfinder"

	local ptype = tvb(OGM.PACKET_TYPE, 1):uint()
	local label = PACKET_TYPES[ptype]
	pinfo.cols.info = "BATMAN " .. (label or string.format("(unknown type 0x%02x)", ptype))

	local tree = root:add(wayfinder, tvb(), "Wayfinder Mesh Protocol")
	tree:add(f.packet_type, tvb(OGM.PACKET_TYPE, 1))

	-- Only the OGM body is decoded in this cut; other sub-types stop after the
	-- protocol/type are labelled.
	if ptype ~= BATADV_IV_OGM or len < OGM.HEADER_LEN then
		return len
	end

	tree:add(f.version, tvb(OGM.VERSION, 1))
	tree:add(f.ttl, tvb(OGM.TTL, 1))
	tree:add(f.flags, tvb(OGM.FLAGS, 1))
	tree:add(f.seqno, tvb(OGM.SEQNO, 4))
	tree:add(f.orig, tvb(OGM.ORIG, 6))
	tree:add(f.prev_sender, tvb(OGM.PREV_SENDER, 6))
	tree:add(f.reserved, tvb(OGM.RESERVED, 1))
	tree:add(f.tq, tvb(OGM.TQ, 1))
	tree:add(f.tvlv_len, tvb(OGM.TVLV_LEN, 2))

	-- The TVLV tail (tvlv_len bytes) follows the fixed header; show it raw,
	-- clamped to what the capture actually holds.
	local tvlv_len = tvb(OGM.TVLV_LEN, 2):uint()
	if tvlv_len > 0 then
		local avail = len - OGM.HEADER_LEN
		local take = math.min(tvlv_len, avail)
		if take > 0 then
			tree:add(f.tvlv, tvb(OGM.HEADER_LEN, take))
		end
	end

	return len
end

-- Frames carrying a Wayfinder LinkFrame appear as Ethernet with type 0x4305.
DissectorTable.get("ethertype"):add(ETH_P_BATMAN, wayfinder)
