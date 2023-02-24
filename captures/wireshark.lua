
-- This is a Lua script for Wireshark
-- Call like:
-- wireshark -X lua_script:wireshark.lua -i eth1 -k

udp_table = DissectorTable.get("udp.port")

-- Channel numbers:
-- 0x01..04 inclusive: CDJ hooked up to channel on mixer
-- 0x11: Rekordbox program
-- 0x21: Mixer

function bits(num)
	local t={}
	for i=7,0,-1 do
		table.insert(t, 1, num:bitfield(i))
	end
	return table.concat(t)
end


function typestr(typ)
	-- Port 50000 types
	if typ==0x00 then
		return 'Bootup0'
	elseif typ==0x02 then
		return 'Bootup2'
	elseif typ==0x04 then
		return 'Bootup4'
	elseif typ==0x06 then
		return 'Heartbeat'
	elseif typ==0x0a then
		return 'Beatinfo or Bootstrap'
	-- Port 50001 types
	elseif typ==0x03 then
		return '0x03'
	elseif typ==0x28 then
		return 'Beatkeeping (basic)'
	elseif typ==0x29 then
		return 'Rekordbox'
	else
		return '???'
	end
end


local deviceTypeMap = {[0x01]="Player", [0x02]="Mixer", [0x04]="Rekordbox"}
local remoteSourceMap = {[2]="Auto", [3]="USB", [4]="Software", [5]="DJM"}

-- Port 50000
djmproto0 = Proto("djm0","DJM0")
local djmproto0_type = ProtoField.uint8("djm0.type", "Type", base.HEX)
djmproto0.fields = {djmproto0_type}

function djmproto0.dissector(buffer, pinfo, tree)
	local subtree = tree:add(djmproto0, buffer(), "XDJ/CDJ/DJM Data")
	subtree:add(buffer(0x00, 10), string.format("Magic: %s (%s)", tostring(buffer(0x00, 10)), tostring(buffer(0x00, 10))=='5173707431576d4a4f4c' and 'good' or 'bad' ))
	local typ = buffer(0x0a, 1):uint()
	tree:add(djmproto0_type, typ)
	pinfo.cols.protocol = string.format("DJ0_%02x", typ)
	subtree:add(buffer(0x0a, 1), string.format("Type: %02x (%s)", typ, typestr(typ)))
	-- This following packet is x01 if being asked directly to the mixer, 0x00 if broadcast
	subtree:add(buffer(0x0b, 1), string.format("Query channel from mixer: %s", tostring(buffer(0x0b, 1)) ))
	subtree:add(buffer(0x0c, 20), "Device name: "..buffer(0x0c, 20):stringz())
	local channel = buffer(0x20, 2):uint()
	subtree:add(buffer(0x20, 2), string.format("x20: %04x (0101 from DJM, 0102 from CDJ, 0103 from Rekordbox)", channel))
	subtree:add(buffer(0x22, 2), string.format("Length: %d (%s)", buffer(0x22, 2):uint(), (buffer(0x22, 2):uint()==buffer:len() and 'good' or 'bad') ) )

	if typ==0x00 then
		pinfo.cols.info = string.format("Type 0x00")
		subtree:add(buffer(0x24, 1), string.format("PacketId: %02x", buffer(0x24,1):uint()) )
		subtree:add(buffer(0x25, 1), string.format("Device type: %02x (%s)", buffer(0x25,1):uint(), deviceTypeMap[buffer(0x25,1):uint()] ) )
		subtree:add(buffer(0x26, 6), string.format("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
			buffer(0x26, 1):uint(), buffer(0x27, 1):uint(), buffer(0x28, 1):uint(),
			buffer(0x29, 1):uint(), buffer(0x2a, 1):uint(), buffer(0x2b, 1):uint())
		)
	elseif typ==0x01 then
		-- Seems to be a reply to 0_x00 when device is plugged into a numbered channel port
		pinfo.cols.info = string.format("You have a direct connection")
		subtree:add(buffer(0x24, 4), string.format("IPaddr: %d.%d.%d.%d", buffer(0x24,1):uint(), buffer(0x25,1):uint(), buffer(0x26,1):uint(), buffer(0x27,1):uint()) )
		subtree:add(buffer(0x28, 6), string.format("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
			buffer(0x28, 1):uint(), buffer(0x29, 1):uint(), buffer(0x2a, 1):uint(),
			buffer(0x2b, 1):uint(), buffer(0x2c, 1):uint(), buffer(0x2d, 1):uint())
		)
		subtree:add(buffer(0x2e, 1), string.format("In reply to: %02x", buffer(0x2e,1):uint()) )
	elseif typ==0x02 then
		pinfo.cols.info = string.format("Type 0x02")
		subtree:add(buffer(0x24, 4), string.format("IPaddr: %d.%d.%d.%d", buffer(0x24,1):uint(), buffer(0x25,1):uint(), buffer(0x26,1):uint(), buffer(0x27,1):uint()) )
		subtree:add(buffer(0x28, 6), string.format("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
			buffer(0x28, 1):uint(), buffer(0x29, 1):uint(), buffer(0x2a, 1):uint(),
			buffer(0x2b, 1):uint(), buffer(0x2c, 1):uint(), buffer(0x2d, 1):uint())
		)
		subtree:add(buffer(0x2e, 1), string.format("Channel: x%02x", buffer(0x2e,1):uint()) ) -- Can be 00 for "Auto"
		subtree:add(buffer(0x2f, 1), string.format("PacketId: %02x", buffer(0x2f,1):uint()) )
		subtree:add(buffer(0x30, 1), string.format("x30: %02x (01 from CDJ, 04 from Rekordbox)", buffer(0x30,1):uint()) )
		local x31Map = {[1]="Auto", [2]="Manual"}
		subtree:add(buffer(0x31, 1), string.format("Channel auto/manual: %02x (%s)", buffer(0x31,1):uint(), x31Map[buffer(0x31,1):uint()]  or "???") )
	elseif typ==0x03 then
		-- Seems to be a reply to 0_x02 when device is plugged into a numbered channel port
		pinfo.cols.info = string.format("Youare plugged into channel %02x", buffer(0x24,1):uint())
		subtree:add(buffer(0x24,1), string.format("Channel: x%02x", buffer(0x24,1):uint()) )
		subtree:add(buffer(0x25,1), string.format("In reply to: %02x", buffer(0x25,1):uint()) )
		subtree:add(buffer(0x26,1), string.format("x26: %02x (=00)", buffer(0x26,1):uint()) )
	elseif typ==0x04 then
		pinfo.cols.info = string.format("Whois the master?")
		subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))
		subtree:add(buffer(0x25, 1), string.format("PacketId: %02x", buffer(0x25, 1):uint()))
	elseif typ==0x05 then
		pinfo.cols.info = string.format("Iam the master!")
		subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))
		subtree:add(buffer(0x25, 1), string.format("x25: %02x", buffer(0x25, 1):uint()))
	elseif typ==0x06 then
		-- Generally always the same data, varies between device
		-- DJM-2000nexus:
		--0000   51 73 70 74 31 57 6d 4a 4f 4c 06 00 44 4a 4d 2d
		--0010   32 30 30 30 6e 65 78 75 73 00 00 00 00 00 00 00
		--0020   01 01 00 36 21 02 74 5e 1c 56 65 a8 c0 a8 00 5a
		--0030   03 00 00 00 02 00
		-- CDJ-2000nexus ch. 2:
		--0000   51 73 70 74 31 57 6d 4a 4f 4c 06 00 43 44 4a 2d
		--0010   32 30 30 30 6e 65 78 75 73 00 00 00 00 00 00 00
		--0020   01 02 00 36 02 01 74 5e 1c 06 a4 ba c0 a8 00 5c
		--0030   03 00 00 00 01 00
		-- CDJ-2000nexus ch. 3:
		--0000   51 73 70 74 31 57 6d 4a 4f 4c 06 00 43 44 4a 2d
		--0010   32 30 30 30 6e 65 78 75 73 00 00 00 00 00 00 00
		--0020   01 02 00 36 03 01 74 5e 1c 35 f3 9f c0 a8 00 5d
		--0030   03 00 00 00 01 00
		
		subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))
		-- CDJ booting up with one mixer on the network with 02(manual) configuration sends x01
		subtree:add(buffer(0x25, 1), string.format("x25: %x [device ID?]", buffer(0x25, 1):uint()))
		subtree:add(buffer(0x26, 6), string.format("MAC: %02x:%02x:%02x:%02x:%02x:%02x",
			buffer(0x26, 1):uint(), buffer(0x27, 1):uint(), buffer(0x28, 1):uint(),
			buffer(0x29, 1):uint(), buffer(0x2a, 1):uint(), buffer(0x2b, 1):uint())
		)
		subtree:add(buffer(0x2c, 4), string.format("IPaddr: %d.%d.%d.%d", buffer(0x2c,1):uint(), buffer(0x2d,1):uint(), buffer(0x2e,1):uint(), buffer(0x2f,1):uint()) )
		subtree:add(buffer(0x30, 1), string.format("x30: %02x (number of devices on network?)", buffer(0x30, 1):uint())) -- 01..04, maybe number of devices on network?
		subtree:add(buffer(0x31, 1), string.format("x31: %02x", buffer(0x31, 1):uint())) -- 01 from Rekordbox, 00 otherwise?
		subtree:add(buffer(0x32, 2), string.format("x32: %04x", buffer(0x32, 2):uint()))
		local x34 = subtree:add(buffer(0x34,1), string.format("x34: %02x (%s)", buffer(0x34,1):uint(), deviceTypeMap[buffer(0x34,1):uint()]) )
		local x35 = subtree:add(buffer(0x35,1), string.format("x35: %02x (%s)", buffer(0x35,1):uint(), bits(buffer(0x35,1)) ) )
		pinfo.cols.info = string.format("Discover")
	elseif typ==0x08 then
		pinfo.cols.info = string.format("Device changing channel")
		subtree:add(buffer(0x24, 1), string.format("Old channel: x%02x", buffer(0x24, 1):uint()))
		subtree:add(buffer(0x25, 4), string.format("IPaddr: %d.%d.%d.%d", buffer(0x25,1):uint(), buffer(0x26,1):uint(), buffer(0x27,1):uint(), buffer(0x28,1):uint()) )

	elseif typ==0x0a then
		pinfo.cols.info = string.format("Device online")
		-- TODO CDJ=0x01, DJM=0x02
		subtree:add(buffer(0x24, 1), string.format("Device type: %02x (%s)", buffer(0x24, 1):uint(), deviceTypeMap[buffer(0x24, 1):uint()]))
	else
		pinfo.cols.info = string.format("Unknown type 0x%02x", typ)
	end
end
-- Register this dissector
udp_table:add(50000, djmproto0)


-- Port 50001
djmproto1 = Proto("djm1","DJM1")
local djmproto1_type = ProtoField.uint8("djm1.type", "Type", base.HEX)
djmproto1.fields = {djmproto1_type}
function djmproto1.dissector(buffer, pinfo, tree)
	local typ = buffer(0x0a, 1):uint()
	tree:add(djmproto1_type, typ)
	pinfo.cols.protocol = string.format("DJ1_%02x", typ)
	local subtree = tree:add(djmproto1, buffer(), "XDJ/CDJ/DJM Data")
	subtree:add(buffer(0x00, 10), string.format("Magic: %s (%s)", tostring(buffer(0x00, 10)), tostring(buffer(0x00, 10))=='5173707431576d4a4f4c' and 'good' or 'bad' ))
	subtree:add(buffer(0x0a, 1), string.format("Type: %02x (%s)", typ, typestr(typ)))
	subtree:add(buffer(0x0b, 20), "Device name: "..buffer(0x0b, 20):stringz())
	subtree:add(buffer(0x1f, 1), string.format("x1f: %02x", buffer(0x1f, 1):uint()) )
	-- This isn't quite right, some setting on the CDJ is now making this output 0x03
	subtree:add(buffer(0x20, 1), string.format("x20: %02x (1 from Rekordbox, 0 otherwise?)", buffer(0x20, 1):uint()))
	local channel = buffer(0x21, 1):uint()
	subtree:add(buffer(0x21, 1), string.format("Channel: x%02x", channel))
	local lengthGood = (0x22+0x02+buffer(0x22, 2):uint() == buffer:len()) and 'good' or 'bad'
	subtree:add(buffer(0x22, 2), string.format("Length of remaining payload: %02x (%d) (%s)", buffer(0x22, 2):uint(), buffer(0x22, 2):uint(), lengthGood) )
	if typ==0x02 then
		-- Port 50001
		local x24Map = {[0]="Start", [1]="Stop", [2]="null"}
		local x24 = subtree:add(buffer(0x24, 1), string.format("Ch1: %02x (%s)", buffer(0x24, 1):uint(), x24Map[buffer(0x24, 1):uint()]))
		local x25 = subtree:add(buffer(0x25, 1), string.format("Ch2: %02x (%s)", buffer(0x25, 1):uint(), x24Map[buffer(0x25, 1):uint()]))
		local x26 = subtree:add(buffer(0x26, 1), string.format("Ch3: %02x (%s)", buffer(0x26, 1):uint(), x24Map[buffer(0x26, 1):uint()]))
		local x26 = subtree:add(buffer(0x27, 1), string.format("Ch4: %02x (%s)", buffer(0x27, 1):uint(), x24Map[buffer(0x27, 1):uint()]))
		pinfo.cols.info = string.format("Start/stop")

	elseif typ==0x03 then
		-- Port 50001
		local x24 = subtree:add(buffer(0x24, 4), string.format("Channels Live: %s%s%s%s",
			buffer(0x24, 1):uint()>0 and '1' or '_',
			buffer(0x25, 1):uint()>0 and '2' or '_',
			buffer(0x26, 1):uint()>0 and '3' or '_',
			buffer(0x27, 1):uint()>0 and '4' or '_'
		) )
		pinfo.cols.info = string.format("DJM channels on-air")

	elseif typ==0x0a then
		pinfo.cols.info = string.format("Type 0x0a")

	elseif typ==0x26 then
		-- Port 50002
		subtree:add(buffer(0x27, 1), string.format("New master: %02x", buffer(0x27, 1):uint()) )
		pinfo.cols.info = string.format("Advertise new master")

	elseif typ==0x27 then
		-- Port 50002
		subtree:add(buffer(0x27, 1), string.format("Channel: x%02x", buffer(0x27, 1):uint()) )
		pinfo.cols.info = string.format("Ack new master")

	elseif typ==0x28 then
		-- Port 50001
		subtree:add(buffer(0x24, 4), string.format("x24: %d (ms/beat?) (before tempoadjust)", buffer(0x24, 4):uint()) )
		subtree:add(buffer(0x28, 4), string.format("x28: %d (ms/2beat) (before tempoadjust)", buffer(0x28, 4):uint()) )
		subtree:add(buffer(0x2c, 4), string.format("x2c: %d (ms to next measure?) (before tempoadjust)", buffer(0x2c, 4):uint()) )
		subtree:add(buffer(0x30, 4), string.format("x30: %d (ms/measure?) (before tempoadjust)", buffer(0x30, 4):uint()) )
		subtree:add(buffer(0x34, 4), string.format("x34: %d (ms to measure after next?) (before tempoadjust)", buffer(0x34, 4):uint()) )
		subtree:add(buffer(0x38, 4), string.format("x38: %d (ms/2measure) (before tempoadjust)", buffer(0x38, 4):uint()) )
		subtree:add(buffer(0x3c, 24), string.format("x10: ff{24}") )
		local tempoAdjust = buffer(0x54, 4):uint()
		local x54 = subtree:add(buffer(0x54, 4), string.format("Tempoadjust: %08x = %03.2f%%", tempoAdjust, tempoAdjust*100.0/0x100000.0) )
		local x54 = subtree:add(buffer(0x58, 2), string.format("x58: %04x [zero?]", buffer(0x58, 2):uint()) )
		subtree:add(buffer(0x5a, 2), string.format("BPM: %03.2f", buffer(0x5a, 2):uint()/100.0) )
		subtree:add(buffer(0x5c, 1), string.format("Beat: %d", buffer(0x5c, 1):uint()) )
		local x54 = subtree:add(buffer(0x5d, 2), string.format("x5d: %04x [zero?]", buffer(0x5d, 2):uint()) )
		subtree:add(buffer(0x5f, 1), string.format("Channel.2: %x", buffer(0x5f, 1):uint()) )
		local channelNum = buffer(0x5f, 1):uint()
		local deviceStr
		if channelNum>4 then
			deviceStr = "Mixer"
		else
			deviceStr = string.format("Chan%d", channelNum)
		end
		pinfo.cols.info = string.format("Beat from %s: %03.2fBPM, |%d", deviceStr, buffer(0x5a, 2):uint()/100.0, buffer(0x5c, 1):uint())

	elseif typ==0x2a then
		-- Port 50002
		pinfo.cols.info = string.format("Sync/master nomination from mixer")
		local x27 = subtree:add(buffer(0x27, 1), string.format("Channel: x%02x", buffer(0x27, 1):uint() ) )
		local x2b = subtree:add(buffer(0x2b, 1), string.format("Update sync assignment: %d (%s)", buffer(0x2b, 1):uint(), bits(buffer(0x2b, 1)) ) )
		if buffer(0x2b,1):bitfield(2,1)>0 then
			x2b:add(buffer(0x2b,1), string.format('..1..... = Free from master'))
		end
		if buffer(0x2b,1):bitfield(3,1)>0 then
			x2b:add(buffer(0x2b,1), string.format('...1.... = Sync to master'))
		end
		if buffer(0x2b,1):bitfield(6,1)>0 then
			x2b:add(buffer(0x2b,1), string.format('......1. = Already master'))
		end
		if buffer(0x2b,1):bitfield(7,1)>0 then
			x2b:add(buffer(0x2b,1), string.format('.......1 = Become master'))
		end

	else
		pinfo.cols.info = string.format("Unknown type 0x%02x", typ)
	end
end
-- Register this dissector
udp_table:add(50001, djmproto1)



-- port 50002
djmproto2 = Proto("djm2","DJM2")
local djmproto2_type = ProtoField.uint8("djm2.type", "Type", base.HEX)
djmproto2.fields = {djmproto2_type}
function djmproto2.dissector(buffer, pinfo, tree)
	local typ = buffer(0x0a, 1):uint()
	tree:add(djmproto2_type, typ)
	pinfo.cols.protocol = string.format("DJ2_%02x", typ)
	local subtree = tree:add(djmproto2, buffer(), "DJM device-to-device")
	subtree:add(buffer(0x00, 10), string.format("Magic: %s (%s)", tostring(buffer(0x00, 10)), tostring(buffer(0x00, 10))=='5173707431576d4a4f4c' and 'good' or 'bad' ))
	subtree:add(buffer(0x0a, 1), string.format("Type: %02x (%s)", typ, typestr(typ)))

	subtree:add(buffer(0x0b, 20), "Device name: "..buffer(0x0b, 20):stringz())

	subtree:add(buffer(0x1f, 1), string.format("x1f: %02x [always x01?]", buffer(0x1f, 1):uint()) )
	subtree:add(buffer(0x20, 1), string.format("x20: %02x [1 from Rekordbox, 0 otherwise?]", buffer(0x20, 1):uint()))
	local channel = buffer(0x21, 1):uint()
	subtree:add(buffer(0x21, 1), string.format("Channel: %02x", channel))
	local lengthGood = (0x22+0x02+buffer(0x22, 2):uint() == buffer:len()) and 'good' or 'bad'
	subtree:add(buffer(0x22, 2), string.format("Length of remaining payload: %d (%s)", buffer(0x22, 2):uint(), lengthGood) )

	if typ==0x05 then
		-- Sent by CDJ when rekordbox connects after a successful NFS mount
		subtree:add(buffer(0x24, 4), string.format("IPaddr: %d.%d.%d.%d", buffer(0x24,1):uint(), buffer(0x25,1):uint(), buffer(0x26,1):uint(), buffer(0x27,1):uint()) )
		subtree:add(buffer(0x28, 4), string.format("Remote channel: %08x", buffer(0x28,4):uint() ) )
		subtree:add(buffer(0x2c, 4), string.format("Remote source: %08x (%s)", buffer(0x2c,4):uint(), remoteSourceMap[buffer(0x2c,4):uint()] ) )
		pinfo.cols.info = string.format("2_05 What about your volumes?")


	elseif typ==0x06 then
		-- rekordbox replies to 0_x05 packet with this
		subtree:add(buffer(0x24, 4), string.format("Remote channel: %08x", buffer(0x24,4):uint() ) )
		subtree:add(buffer(0x28, 4), string.format("Remote source: %08x (%s)", buffer(0x28,4):uint(), remoteSourceMap[buffer(0x28,4):uint()] ) )
		subtree:add(buffer(0x2c, 64), string.format("x2c: %s", buffer(0x2c,64):ustringz() ) )
		subtree:add(buffer(0x6c, 40), string.format("x6c: %s", buffer(0x6c,40):ustringz() ) )
		subtree:add(buffer(0xa6, 2), string.format("Number of tracks: %d", buffer(0xa6,2):uint() ) )
		subtree:add(buffer(0xa8, 2), string.format("xa8: %04x", buffer(0xa8,2):uint() ) )
		subtree:add(buffer(0xaa, 2), string.format("xaa: %04x", buffer(0xaa,2):uint() ) )
		subtree:add(buffer(0xac, 2), string.format("xac: %04x", buffer(0xac,2):uint() ) )
		-- Watch out, because of size limits we're only reading 4 of 8 bytes for this number, which is usually good enough
		subtree:add(buffer(0xae, 2), string.format("Number of playlists: %d", buffer(0xae,2):uint() ) )
		subtree:add(buffer(0xb0, 8), string.format("Total size: %d MB", buffer(0xb2,4):uint()/1000000*0x10000 ) )
		subtree:add(buffer(0xb8, 8), string.format("Free size: %d MB", buffer(0xba,4):uint()/1000000*0x10000 ) )
		pinfo.cols.info = string.format("2_06 Yea I got volumes")


	elseif typ==0x0a then
		local x24 = subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))
		local x25 = subtree:add(buffer(0x25, 3), string.format("x25: %06x", buffer(0x25, 3):uint()))
		local x28 = subtree:add(buffer(0x28, 4), string.format("x28: %08x (sourceid)", buffer(0x28, 4):uint() ) )
		local x2f = subtree:add(buffer(0x2c, 4), string.format("x2c: %04x [trackid]", buffer(0x2c, 4):uint() ) )
		local x33 = subtree:add(buffer(0x33, 1), string.format("Playlist number: %d (0x%02x)", buffer(0x33, 1):uint(), buffer(0x33, 1):uint() ) )
		local x33 = subtree:add(buffer(0x34, 4), string.format("x34: %04x (%d)", buffer(0x34, 4):uint(), buffer(0x34, 4):uint() ) )
		local x33 = subtree:add(buffer(0x38, 4), string.format("x38: %04x (%d)", buffer(0x38, 4):uint(), buffer(0x38, 4):uint() ) )
		local x3c = subtree:add(buffer(0x3c, 4), string.format("x3c: %04x [always ff{4} or 00{4}]", buffer(0x3c, 4):uint() ) )
		local x3c = subtree:add(buffer(0x40, 4), string.format("x40: %04x [always 00{4}]", buffer(0x40, 4):uint() ) )
		local x3c = subtree:add(buffer(0x44, 4), string.format("x44: %04x [always 3 ??]", buffer(0x44, 4):uint() ) )
		local x3c = subtree:add(buffer(0x48, 4), string.format("x48: %04x [1000 if CD, else 0000]", buffer(0x48, 4):uint() ) )
		local x4c = subtree:add(buffer(0x4c, 12), string.format("Disc id: %08x%08x%08x", buffer(0x4c, 4):uint(), buffer(0x50, 4):uint(), buffer(0x54, 4):uint() ) )
		local x58 = subtree:add(buffer(0x58, 4), string.format("x58: %08x", buffer(0x58, 4):uint() ) )
		local x58 = subtree:add(buffer(0x5c, 4), string.format("x5c: %08x", buffer(0x5c, 4):uint() ) )
		local x58 = subtree:add(buffer(0x60, 4), string.format("x60: %08x", buffer(0x60, 4):uint() ) )
		local x58 = subtree:add(buffer(0x64, 2), string.format("x64: %04x", buffer(0x64, 4):uint() ) )
		local x66 = subtree:add(buffer(0x66, 1), string.format("Disc ejecting: %02x", buffer(0x66, 1):uint()) )

		-- USB lamp
		local x6aMap = {[4]="off", [6]="ON"}
		local x6a = subtree:add(buffer(0x6a, 1), string.format("USB lamp: %02x (%s)", buffer(0x6a, 1):uint(), x6aMap[buffer(0x6a, 1):uint()] or "???" ) )

		-- SD lamp
		local x6bMap = {[4]="off", [6]="ON"}
		local x6b = subtree:add(buffer(0x6b, 1), string.format("SD lamp: %02x (%s)", buffer(0x6b, 1):uint(), x6bMap[buffer(0x6b, 1):uint()] or "???" ) )

		-- USB status
		local x6fMap = {[0]="Mounted", "???", "About to eject", "Ejecting", "Not mounted"}
		local x6f = subtree:add(buffer(0x6f, 1), string.format("USB status: %02x (%s)", buffer(0x6f, 1):uint(), x6fMap[buffer(0x6f, 1):uint()] ) )

		-- SD card status
		local x73Map = {[0]="Mounted", "???", "About to eject", "Ejecting", "Not mounted"}
		local x73 = subtree:add(buffer(0x73, 1), string.format("SDCard status: %02x (%s)", buffer(0x73, 1):uint(), x73Map[buffer(0x73, 1):uint()] ) )

		-- Disc status
		local x76Map = {[0]="Empty", [4]="Mounted"}
		local x76 = subtree:add(buffer(0x76, 1), string.format("Disc status: %02x (%s)", buffer(0x76, 1):uint(), x76Map[buffer(0x76, 1):uint()] ) )

		local x7bMap = {[0]="Init", [2]="Loading", [3]="Playing", [5]="Paused", [6]="Stopped/Cue", [7]="Cue playing", [9]="Searching"}
		local x7b = subtree:add(buffer(0x7b, 1), string.format("Play state: %02x (%s)", buffer(0x7b, 1):uint(), x7bMap[buffer(0x7b, 1):uint()] ) )
		-- 06 (0110) when track is loaded, cue solid, play/pause blinking
		-- 05 (0101) when track paused, away from cuepoint, both lamps blinking
		-- 03 (0011) when track playing, both lamps solid
		-- 02 Loading or cannot play

		-- four-character version string
		local x7c = subtree:add(buffer(0x7c, 4), string.format("Firmware version: %s", buffer(0x7c, 4):string() ) )

		-- Number of times the device has been master, x2? WHY? What is this?
		local x86 = subtree:add(buffer(0x86, 2), string.format("x86: %04x", buffer(0x86, 2):uint() ) )

		local x88 = subtree:add(buffer(0x88, 2), string.format("x88: %04x (%s %s)", buffer(0x88, 2):uint(), bits(buffer(0x88,1)), bits(buffer(0x89,1)) ) )
		if buffer(0x88,1):bitfield(7,1)>0 then
			x88:add(buffer(0x88,1), string.format('.......1 ........ = Seeking/buffering data'))
		end
		if buffer(0x89,1):bitfield(0,1)>0 then
			--x88:add(buffer(0x89,1), string.format('........ 1....... = 0x0080 (default at boot)'))
		end
		if buffer(0x89,1):bitfield(1,1)>0 then
			x88:add(buffer(0x89,1), string.format('........ .1...... = Device is playing and track annotated'))
		end
		if buffer(0x89,1):bitfield(2,1)>0 then
			x88:add(buffer(0x89,1), string.format('........ ..1..... = Device is master'))
		end
		if buffer(0x89,1):bitfield(3,1)>0 then
			x88:add(buffer(0x89,1), string.format('........ ...1.... = Device is synced'))
		end
		if buffer(0x89,1):bitfield(4,1)>0 then
			--x88:add(buffer(0x89,1), string.format('........ ....1... = 0x0008 (default at boot)'))
		end
		if buffer(0x89,1):bitfield(5,1)>0 then
			--x88:add(buffer(0x89,1), string.format('........ .....1.. = 0x0004 (default at boot)'))
		end
		if buffer(0x89,1):bitfield(6,1)>0 then
			x88:add(buffer(0x89,1), string.format('........ ......1. = 0x0002'))
		end
		if buffer(0x89,1):bitfield(7,1)>0 then
			x88:add(buffer(0x89,1), string.format('........ .......1 = 0x0001'))
		end

		local x8a = subtree:add(buffer(0x8a, 1), string.format("x8a: %02x [Random counter that counts to 0xff and stops for some reason]", buffer(0x8a, 1):uint() ) )
		local x8b = subtree:add(buffer(0x8b, 1), string.format("x8b: %02x (%s)", buffer(0x8b, 1):uint(), bits(buffer(0x8b, 1)) ) )
		if buffer(0x8b,1):bitfield(5,1)>0 then
			x8b:add(buffer(0x8b,1), string.format('........ .....1.. = Device is stopped or stopping with platter depressed'))
		end

		local tempoAdj8c = buffer(0x8c, 4):uint()
		local x8c = subtree:add(buffer(0x8c, 4), string.format("Tempoadjust_8c: %08x = %03.2f%%", tempoAdj8c, tempoAdj8c*100.0/0x100000.0) )

		local x90 = subtree:add(buffer(0x90, 2), string.format("x90: %04x (%s %s)", buffer(0x90, 2):uint(), bits(buffer(0x90, 1)), bits(buffer(0x91, 1)) ) )
		if buffer(0x90,1):bitfield(0,1)>0 then
			x90:add(buffer(0x90,1), string.format('1....... = Rekordbox sourced track?'))
		end

		local trackTempo = buffer(0x92, 2):uint()
		local trackTempoStr = trackTempo==0xffff and 'unknown' or string.format('%03.2f', trackTempo/100)
		local x92 = subtree:add(buffer(0x92, 2), string.format("Track tempo: %04x (%s)", trackTempo, trackTempoStr) )

		-- Always 0x7fffffff ?
		local x94 = subtree:add(buffer(0x94, 4), string.format("x94: %08x", buffer(0x94, 4):uint()) )

		local x98 = subtree:add(buffer(0x98, 4), string.format("Tempoadjust_98: %08x = %03.2f%%", buffer(0x98, 4):uint(), buffer(0x98, 4):uint()*100.0/0x100000.0) )

		local x9c = subtree:add(buffer(0x9c, 3), string.format("x9c: %06x (%s %s %s)", buffer(0x9c, 3):uint(), bits(buffer(0x9c, 1)), bits(buffer(0x9d, 1)), bits(buffer(0x9e, 4)) ) )
		if buffer(0x9d,1):bitfield(7,1)>0 then
			x9c:add(buffer(0x9d,1), string.format('........ .......1 ........ = Always on?'))
		end
		if buffer(0x9d,1):bitfield(4,1)>0 then
			x9c:add(buffer(0x9d,1), string.format('........ ....1... ........ = Playing forwards at full speed'))
		end
		if buffer(0x9e,1):bitfield(7,1)>0 then
			x9c:add(buffer(0x9e,1), string.format('........ ........ .......1 = This device master (1)'))
		end
		if buffer(0x9e,1):bitfield(6,1)>0 then
			x9c:add(buffer(0x9e,1), string.format('........ ........ ......1. = This device master (2)'))
		end

		local x9f = subtree:add(buffer(0x9f, 1), string.format("Next master: %02x", buffer(0x9f, 1):uint() ) )

		local xa2 = subtree:add(buffer(0xa2, 2), string.format("Beats since start: %d", buffer(0xa2, 2):uint()) )
		if buffer(0xa2, 2):uint()==0xffff then
			xa2:add(buffer(0xa3,1), string.format('xFFFF = Unknown'))
		end

		local xa4 = subtree:add(buffer(0xa4, 1), string.format("xa4: %02x (%s)", buffer(0xa4, 1):uint(), bits(buffer(0xa4, 1)) ) )
		if buffer(0xa4,1):bitfield(7,1)>0 then
			xa4:add(buffer(0xa4,1), string.format('.......1 = Beat countdown unknown?'))
		end

		local beatsToCue = buffer(0xa5, 1):uint()
		local xa5 = subtree:add(buffer(0xa5, 1), string.format("Beats to next cuepoint: %d (%d.%d)", beatsToCue, beatsToCue/4, beatsToCue%4) )

		local xa6 = subtree:add(buffer(0xa6, 1), string.format("Beat: %d", buffer(0xa6, 1):uint()) )
		local trackBeat = buffer(0xa2, 2):uint()
		local measureBeat = buffer(0xa6, 1):uint()

		local xc0 = subtree:add(buffer(0xc0, 4), string.format("Tempoadjust_c0 slider position: %08x = %03.2f%%", buffer(0xc0, 4):uint(), buffer(0xc0, 4):uint()*100.0/0x100000.0) )
		local xc4 = subtree:add(buffer(0xc4, 4), string.format("Tempoadjust_c4 play speed/playing: %08x = %03.2f%%", buffer(0xc4, 4):uint(), buffer(0xc4, 4):uint()*100.0/0x100000.0) )
		local xc8 = subtree:add(buffer(0xc8, 4), string.format("Packet id: %08x", buffer(0xc8, 4):uint() ) )

		pinfo.cols.info = string.format("Beatinfo %d |%d", trackBeat, measureBeat)

	elseif typ==0x0d then
		-- Sent by DJM if it has a file that can be played
		pinfo.cols.info = string.format("2_0d I've got files")
		subtree:add(buffer(0x24, 4), string.format("x24: %x (always 0x00000021)", buffer(0x24, 4):uint(), lengthGood) )
		subtree:add(buffer(0x28, 4), string.format("x28: %x (always 0x00000001)", buffer(0x28, 4):uint(), lengthGood) )
		subtree:add(buffer(0x2c, 0x40), string.format("Filename: %s", buffer(0x2c,0x40):ustringz() ) )
		subtree:add(buffer(0x6c, 0x40), string.format("Path: %s", buffer(0x6c,0x40):ustringz() ) )
		subtree:add(buffer(0xac, 0x17), string.format("Comment: %s", buffer(0xac,0x17):ustringz() ) )

	elseif typ==0x10 then
		-- Sent by CDJ to Rekordbox after first 0_06 packet with channel number>0x10
		-- Seems to be asking for "hey what can you export to me"
		-- Zero payload
		pinfo.cols.info = string.format("2_10 Can you export?", measure, beat)

	elseif typ==0x11 then
		-- Seems to be a reply to 2_10
		-- The CDJ will attempt to NFS mount the sender after receiving this packet
		pinfo.cols.info = string.format("2_11 Yeah I can export", measure, beat)
		subtree:add(buffer(0x24, 1), string.format("Channel?: %02x", buffer(0x24,1):uint() ) )
		subtree:add(buffer(0x25, 1), string.format("x25: %02x", buffer(0x25,1):uint() ) )
		subtree:add(buffer(0x26, 1), string.format("x26: %02x", buffer(0x26,1):uint() ) )
		subtree:add(buffer(0x27, 1), string.format("x27: %02x", buffer(0x27,1):uint() ) )
		subtree:add(buffer(0x28, 256), string.format("Hostname: %s", buffer(0x28,256):ustringz() ) )

	elseif typ==0x16 then
		-- Sent from Rekordbox to CDJ
		-- Seems to be reply to a 0_x06 packet from device
		-- Causes CDJ to try a portmap then an export of the sending device
		-- Zero payload
		pinfo.cols.info = string.format("2_16 Mount plz", measure, beat)

	elseif typ==0x19 then
		-- Instruction to load track to device
		subtree:add(buffer(0x24, 4), string.format("x24: %08x", buffer(0x24,4):uint() ) )
		subtree:add(buffer(0x28, 4), string.format("x28: %08x (Channel/sourceid)", buffer(0x28,4):uint() ) )
		subtree:add(buffer(0x2c, 4), string.format("x2c: %08x (Trackid)", buffer(0x2c,4):uint() ) )
		subtree:add(buffer(0x30, 4), string.format("x30: %08x", buffer(0x30,4):uint() ) )
		subtree:add(buffer(0x34, 4), string.format("x34: %08x", buffer(0x34,4):uint() ) )
		subtree:add(buffer(0x38, 4), string.format("x38: %08x", buffer(0x38,4):uint() ) )
		subtree:add(buffer(0x3c, 4), string.format("x3c: %08x", buffer(0x3c,4):uint() ) )
		subtree:add(buffer(0x40, 4), string.format("x40: %08x", buffer(0x40,4):uint() ) )
		subtree:add(buffer(0x44, 4), string.format("x44: %08x", buffer(0x44,4):uint() ) )
		subtree:add(buffer(0x48, 4), string.format("x48: %08x", buffer(0x48,4):uint() ) )
		subtree:add(buffer(0x4c, 4), string.format("x4c: %08x", buffer(0x4c,4):uint() ) )
		subtree:add(buffer(0x50, 4), string.format("x50: %08x", buffer(0x50,4):uint() ) )
		subtree:add(buffer(0x54, 4), string.format("x54: %08x", buffer(0x54,4):uint() ) )
		pinfo.cols.info = string.format("Load track", measure, beat)

	elseif typ==0x1a then
		-- Device responds with ack
		subtree:add(buffer(0x24, 4), string.format("x24: %08x", buffer(0x24,4):uint() ) )
		pinfo.cols.info = string.format("Ack load track", measure, beat)

	elseif typ==0x1c then
		-- This is a response after "ack load track"
		-- Probably comes up only if a track is playing and "Track Lock" is set on
		pinfo.cols.info = string.format("Cannot load track")

	elseif typ==0x1d then
		-- I think this is sent whenever a cuepoint is modified
		pinfo.cols.info = string.format("Cuepoint info modified")

	elseif typ==0x29 then
		-- Ports 50002
		local x24 = subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))
		local x27 = subtree:add(buffer(0x27, 1), string.format("x27: %02x (%s)", buffer(0x27, 1):uint(), bits(buffer(0x27, 1)) ) )
		if buffer(0x27,1):bitfield(2,1)>0 then
			x27:add(buffer(0x27,2), string.format('..1..... = Mixer is master'))
		end
		local x2e = subtree:add(buffer(0x2e, 1), string.format("Current BPM: %03.2f", buffer(0x2e, 1):uint()/100 ) )
		local x37 = subtree:add(buffer(0x37, 1), string.format("Current beat: %d", buffer(0x37, 1):uint() ) )
		pinfo.cols.info = string.format("Master packet of some sort")

	elseif typ==0x35 then
		-- Ports 50002
		pinfo.cols.info = string.format("Request settings")
		subtree:add(buffer(0x24, 1), string.format("x24: %02x", buffer(0x24,1):uint() ) )
		subtree:add(buffer(0x25, 1), string.format("x25: %02x", buffer(0x25,1):uint() ) )
		subtree:add(buffer(0x26, 1), string.format("x26: %02x", buffer(0x26,1):uint() ) )
		subtree:add(buffer(0x27, 1), string.format("x27: %02x", buffer(0x27,1):uint() ) )

	elseif typ==0x36 then
		-- Ports 50002
		pinfo.cols.info = string.format("Reply settings")
		local x24 = subtree:add(buffer(0x24, 1), string.format("Channel: x%02x", buffer(0x24, 1):uint()))

	else
		pinfo.cols.info = string.format("Unknown type 0x%02x", typ)
	end
end
-- Register this dissector
udp_table:add(50002, djmproto2)


-- port 50004
djmproto4 = Proto("djm4","DJM4")
function djmproto4.dissector(buffer, pinfo, tree)
	local subtree = tree:add(djmproto2, buffer(), "DJMcue")
	subtree:add(buffer(0x00, 10), string.format("Magic: %s (%s)", tostring(buffer(0x00, 10)), tostring(buffer(0x00, 10))=='5173707431576d4a4f4c' and 'good' or 'bad' ))
	local typ = buffer(0x0a, 1):uint()
	pinfo.cols.protocol = string.format("DJ4_%02x", typ)
	subtree:add(buffer(0x0a, 1), string.format("Type: %02x (%s)", typ, typestr(typ)))

	subtree:add(buffer(0x0b, 20), "Device name: "..buffer(0x0b, 20):stringz())

	subtree:add(buffer(0x1f, 1), string.format("x1f: %02x [always x01?]", buffer(0x1f, 1):uint()) )
	subtree:add(buffer(0x20, 1), string.format("x20: %02x [1 from Rekordbox, 0 otherwise?]", buffer(0x20, 1):uint()))
	local channel = buffer(0x21, 1):uint()
	subtree:add(buffer(0x21, 1), string.format("Channel: x%02x", channel))

	local lengthGood = (0x22+0x02+buffer(0x22, 2):uint() == buffer:len()) and 'good' or 'bad'
	subtree:add(buffer(0x22, 2), string.format("Length of remaining payload: %d (%s)", buffer(0x22, 2):uint(), lengthGood) )

	if typ==0x20 then
		subtree:add(buffer(0x28, 1), string.format("Request Link audio stream: %02x", buffer(0x28, 1):uint()) )
		subtree:add(buffer(0x29, 1), string.format("x29: %02x [last byte, always 0x11?]", buffer(0x29, 1):uint()) )
	elseif typ==0x1e then
		subtree:add(buffer(0x28, 1), string.format("Request Link audio stream: %02x", buffer(0x28, 1):uint()) )
		subtree:add(buffer(0x29, 1), string.format("x29: %02x [last byte, always 0x11? chan id?]", buffer(0x29, 1):uint()) )
	else
		pinfo.cols.info = string.format("Unknown type 0x%02x", typ)
	end
end
-- Register this dissector
udp_table:add(50004, djmproto4)
