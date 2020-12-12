using System;
using System.Collections.Generic;
using System.Linq;

namespace Parsel
{

	public static class ParseUtils
	{
		public static IEnumerable<ByteRange> ParseFile(IList<string> fData)
		{
			var parsedBytes = new List<ByteRange>();

			// Split Packets

			var startPacketIndex = 0;
			var endIndex = 0;
			var packetNumber = 0;
			var byteList = new List<byte>();
			
			foreach (var line in fData)
			{
				var offset = Convert.ToInt32(line.Split(' ').ToArray()[0], 16);
				if (offset == 0 && startPacketIndex != endIndex)
				{
					parsedBytes.Add(new ByteRange($"Packet {packetNumber}", startPacketIndex, endIndex, byteList));
					packetNumber += 1;

					startPacketIndex = endIndex;

					byteList = new List<byte>();
				}
				var strBytes = line.Split(' ').ToList();
				byteList.AddRange(strBytes.GetRange(1, strBytes.Count - 1).Select(b => Convert.ToByte(b, 16))); 
				endIndex += line.Length + 1;
			}
			parsedBytes.Add(new ByteRange($"Packet {packetNumber}", startPacketIndex, endIndex, byteList));
			
			return parsedBytes;
		}

		public static ByteRange ParseEthernet(ByteRange packet, string data)
		{
			// Destination MAC
			var dstMacBytes = packet.GetByteList().GetRange(0, 6);
			// Source MAC
			var srcLacBytes = packet.GetByteList().GetRange(6, 6);
			// Type
			var typeBytes = packet.GetByteList().GetRange(12, 2);
			
			var dstMac = string.Join(':', dstMacBytes.Select(b => b.ToString("X2")));
			var srcMac = string.Join(':', srcLacBytes.Select(b => b.ToString("X2")));
			var typeStr = string.Join("", typeBytes.Select(b => b.ToString("X2")));
			var type = Convert.ToInt32(typeStr, 16) switch
			{
				2048 => "IPv4",
				2054 => "ARP",
				34525 => "IPv6",
				_ => "Unsupported"
			};
			type += $" (0x{typeStr})";

			var cursor = ModelHelper.CursorSetter(packet.GetRangeStart(), data);
			
			var ethernetLayer = 
				new ByteRange("Ethernet II", cursor,ModelHelper.ByteShifter(cursor, data, 14),packet.GetByteList().GetRange(0,14),
					$"Src: {srcMac}, Dst: {dstMac}, Type: {type}");
			var dstIpRange = new ByteRange("Dst MAC", cursor, 
				ModelHelper.ByteShifter(cursor, data, 6), dstMacBytes, dstMac);
			var srcIpRange = new ByteRange("Src MAC", dstIpRange.GetRangeEnd(), 
				ModelHelper.ByteShifter(dstIpRange.GetRangeEnd(), data, 6), srcLacBytes, srcMac);
			var typeRange = new ByteRange("Type", dstIpRange.GetRangeEnd() + 18,
				ModelHelper.ByteShifter(srcIpRange.GetRangeEnd(), data, 2), typeBytes, type);
			
			ethernetLayer.AddChild(typeRange);
			ethernetLayer.AddChild(dstIpRange);
			ethernetLayer.AddChild(srcIpRange);

			return ethernetLayer;
			
			
		}

		public static ByteRange ParseIp(ByteRange packet, string data)
		{
			// Version
			var firstByteAsList = new List<byte>() {packet.GetByteList()[14]};
			var first = packet.GetByteList()[14].ToString("X2");
			var version = Convert.ToInt32(first.Substring(0,1), 16);

			// Header Length
			var headerBytes = first.Substring(1,1);
			var headerLength = Convert.ToInt32(headerBytes, 16) * 4;
			
			// Type of service
			var tos = packet.GetByteList()[15].ToString("X2");
			var tosBytesAsList = new List<byte> {packet.GetByteList()[15]};
			
			// Total Length
			var tLengthBytes = packet.GetByteList().GetRange(16, 2);
			var totalLength = Convert.ToInt32(string.Join("", tLengthBytes.Select(b => b.ToString("X2"))), 16);
			
			// Identification
			var identificationBytes = packet.GetByteList().GetRange(18, 2);
			var identification = "0x" + string.Join("", identificationBytes.Select(b => b.ToString("X2")));
			
			// Fragmentation
			var fragBytes = packet.GetByteList().GetRange(20, 2);
			var flagsStr = ToHexRepresentation(fragBytes);
			var frag = Convert.ToString(
				Convert.ToInt32(
					flagsStr.Substring(2,4), 16), 2).PadLeft(16,'0');
			
			
			// Flags
			var fragFlags = frag.Substring(0, 3);
			var reserved = Convert.ToInt32(fragFlags.Substring(0,1));
			var dontFrag = Convert.ToInt32(fragFlags.Substring(1,1));
			var moreFrag = Convert.ToInt32(fragFlags.Substring(2,1));
			
			// Offset
			var fragOffset = Convert.ToInt32(frag.Substring(3, 13), 2) * 8;

			// TTL
			var ttlByte = packet.GetByteList().GetRange(22, 1);
			var ttl = Convert.ToInt32(ttlByte[0]);
			
			// Protocol
			var protocolBytes = packet.GetByteList().GetRange(23,1);
			var protocolStr = protocolBytes[0].ToString();
			var protocol = Convert.ToInt32(protocolStr) switch
			{
				1 => "ICMP",
				6 => "TCP",
				17 => "UDP",
				_ => "Unsupported"
			};
			
			// Checksum
			var checksumBytes = packet.GetByteList().GetRange(24, 2);
			var checksum = ToHexRepresentation(checksumBytes);
			
			// Source Ip
			var srcIpBytes = packet.GetByteList().GetRange(26, 4);
			var srcIp = string.Join('.', srcIpBytes.Select(b => b.ToString()));
			
			// Source Ip
			var dstIpBytes = packet.GetByteList().GetRange(30, 4);
			var dstIp = string.Join('.', dstIpBytes.Select(b => b.ToString()));

			// Make ByteRanges
			
			var cursor = ModelHelper.ByteShifter(packet.GetRangeStart(), data, 14);
			
			var ipv4 = new ByteRange("IPv4", cursor, ModelHelper.ByteShifter(cursor, data, headerLength), 
				packet.GetByteList().GetRange(14,headerLength), $"Src: {srcIp}, Dst: {dstIp}");

			var versionRange = new ByteRange("Version", cursor, ModelHelper.ByteShifter(cursor, data, 1), 
				firstByteAsList, version.ToString());
			ipv4.AddChild(versionRange);
			
			var ihlRange = new ByteRange("Header Length", cursor, ModelHelper.ByteShifter(cursor, data, 1),
				firstByteAsList, $"{headerLength.ToString()} bytes ({Convert.ToInt32(headerBytes, 16)})");
			ipv4.AddChild(ihlRange);

			var tosRange = new ByteRange("Type of service", ihlRange.GetRangeEnd(), ModelHelper.ByteShifter(ihlRange.GetRangeEnd(), data, 1),
				tosBytesAsList, $"{ToHexRepresentation(tosBytesAsList)} ({tos})");
			ipv4.AddChild(tosRange);

			var totalLengthRange = new ByteRange("Total Length", 
				tosRange.GetRangeEnd(), ModelHelper.ByteShifter(tosRange.GetRangeEnd(), data, 2),
				tLengthBytes,$"{ToHexRepresentation(tLengthBytes)} ({totalLength} bytes)");
			ipv4.AddChild(totalLengthRange);

			var identificationRange = new ByteRange("Identification",
				totalLengthRange.GetRangeEnd(), ModelHelper.ByteShifter(totalLengthRange.GetRangeEnd(), data, 2),
				identificationBytes, $"{identification}");
			ipv4.AddChild(identificationRange);

			var flags = new ByteRange("Flags: ",
				identificationRange.GetRangeEnd(), ModelHelper.ByteShifter(identificationRange.GetRangeEnd(), data, 2),
				fragBytes, $"{flagsStr}");
			ipv4.AddChild(flags);

			var reservedFlagRange = new ByteRange($"{reserved}... .... .... ....",
				identificationRange.GetRangeEnd(), ModelHelper.ByteShifter(identificationRange.GetRangeEnd(), data, 2),
				fragBytes, $"Reserved Bit: {(reserved == 1 ? "Set" : "Not set")}");

			var dontFragRange = new ByteRange($".{dontFrag}.. .... .... ....",
				identificationRange.GetRangeEnd(), ModelHelper.ByteShifter(identificationRange.GetRangeEnd(), data, 2),
				fragBytes, $"Don't fragment: {(dontFrag == 1 ? "Set" : "Not set")}");

			var moreFragRange = new ByteRange($"..{moreFrag}. .... .... ....",
				identificationRange.GetRangeEnd(), ModelHelper.ByteShifter(identificationRange.GetRangeEnd(), data, 2),
				fragBytes, $"More fragments: {(moreFrag == 1 ? "Set" : "Not set")}");

			flags.AddChild(reservedFlagRange);
			flags.AddChild(dontFragRange);
			flags.AddChild(moreFragRange);
			
			var fragOffRange = new ByteRange("Fragment offset", 
				identificationRange.GetRangeEnd(), ModelHelper.ByteShifter(identificationRange.GetRangeEnd(), data, 2),
				fragBytes, fragOffset.ToString());
			ipv4.AddChild(fragOffRange);

			var ttlRange = new ByteRange("Time to live",
				fragOffRange.GetRangeEnd(), ModelHelper.ByteShifter(fragOffRange.GetRangeEnd(), data, 1),
				ttlByte, $"{ToHexRepresentation(ttlByte)} ({ttl.ToString()})");
			ipv4.AddChild(ttlRange);

			var protocolRange = new ByteRange("Protocol",
				ttlRange.GetRangeEnd(), ModelHelper.ByteShifter(ttlRange.GetRangeEnd(), data, 1),
				protocolBytes, $"{protocol} ({ToHexRepresentation(protocolBytes)}/{protocolStr})");
			ipv4.AddChild(protocolRange);

			var headerChecksumRange = new ByteRange("Header checksum",
				protocolRange.GetRangeEnd(), ModelHelper.ByteShifter(protocolRange.GetRangeEnd(), data, 2),
				checksumBytes, checksum);
			ipv4.AddChild(headerChecksumRange);

			var srcIpRange = new ByteRange("Source IP",
				headerChecksumRange.GetRangeEnd(), ModelHelper.ByteShifter(headerChecksumRange.GetRangeEnd(), data, 4),
				srcIpBytes, srcIp);
			ipv4.AddChild(srcIpRange);

			var dstIpRange = new ByteRange("Destination IP",
				srcIpRange.GetRangeEnd(), ModelHelper.ByteShifter(srcIpRange.GetRangeEnd(), data, 4),
				dstIpBytes, dstIp);
			ipv4.AddChild(dstIpRange);
			
			const int treatedBytes = 20;

			if(headerLength < 20) throw new FormatException($"IP header must be at least 20 bytes, got {headerLength}");
			if (headerLength == treatedBytes) return ipv4;
			
			// Options Range
			
			var optionsLength = headerLength - 20;

			var optionsRange = new ByteRange("IP Options", dstIpRange.GetRangeEnd(),
				ModelHelper.ByteShifter(dstIpRange.GetRangeEnd(), data, optionsLength), packet.GetByteList().GetRange(34, optionsLength));
			
			// Increment this whenever a byte is treated within option parsing
			var treatedOptionBytes = 0;
			
			// Last Index treated for string cursor
			var lastIndex = dstIpRange.GetRangeEnd();

			while (headerLength > treatedBytes + treatedOptionBytes)
			{
				// Get byte containing type of option
				var optionTypeByte = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
				treatedOptionBytes++;

				// Get option type as int
				var optionType = Convert.ToInt32(optionTypeByte[0]);

				// Set start of index as last shifted index
				var rangeStart = lastIndex;
				
				// End of options list reached
				if (optionType == 0)
				{
					var endOptionsRange = new ByteRange("End of Options List", rangeStart, lastIndex, optionTypeByte);
					endOptionsRange.AddChild(new ByteRange("Type", rangeStart, lastIndex, optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType}"));
					optionsRange.AddChild(endOptionsRange);
					break;
				}
				
				var optionStart = treatedOptionBytes + 33;
				switch (optionType)
				{
					case 1:
						// Shift end of index to end of option
						lastIndex = ModelHelper.ByteShifter(lastIndex, data, 1);

						var noOpRange = new ByteRange("No Operation", rangeStart, lastIndex, optionTypeByte);
						noOpRange.AddChild(new ByteRange("Type", rangeStart, lastIndex, optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType})"));
						optionsRange.AddChild(noOpRange);
						break;
					case 68:
						// Length
						var tsLengthBytes = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
						treatedOptionBytes++;
						var tsLength = Convert.ToInt32(tsLengthBytes[0].ToString("X2"), 16);
						lastIndex = ModelHelper.ByteShifter(lastIndex, data, tsLength);
						
						var tsRange = new ByteRange("Time Stamp", rangeStart, lastIndex, 
							packet.GetByteList().GetRange(optionStart, tsLength),
							"No further details processed");
						tsRange.AddChild(new ByteRange("Type", rangeStart, lastIndex, optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType})"));
						
						treatedOptionBytes += tsLength - 2;
						optionsRange.AddChild(tsRange);
						break;
					
					case 131:
						// Length
						var lrLengthBytes = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
						treatedOptionBytes++;
						var lrLength = Convert.ToInt32(lrLengthBytes[0].ToString("X2"), 16);
						lastIndex = ModelHelper.ByteShifter(lastIndex, data, lrLength);
						
						var lrRange = new ByteRange("Loose Routing", rangeStart, lastIndex, 
							packet.GetByteList().GetRange(optionStart, lrLength),
							"No further details processed");
						lrRange.AddChild(new ByteRange("Type", rangeStart, lastIndex, optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType})"));
						
						treatedOptionBytes += lrLength - 2;
						optionsRange.AddChild(lrRange);
						break;
					
					case 137:
						// Length
						var srLengthBytes = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
						treatedOptionBytes++;
						var srLength = Convert.ToInt32(srLengthBytes[0].ToString("X2"), 16);
						lastIndex = ModelHelper.ByteShifter(lastIndex, data, srLength);
						
						var srRange = new ByteRange("Strict Routing", rangeStart, lastIndex, 
							packet.GetByteList().GetRange(optionStart, srLength),
							"No further details processed");
						srRange.AddChild(new ByteRange("Type", rangeStart, lastIndex, optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType})"));
						
						treatedOptionBytes += srLength - 2;
						optionsRange.AddChild(srRange);
						break;

					case 7:
						// 33 instead of 34 to account for the treated Type byte
						
						// Length
						var rcRouteLengthByte = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
						treatedOptionBytes++;
						var rcRouteLength = Convert.ToInt32(rcRouteLengthByte[0].ToString("X2"), 16);
						
						var optionEnd = optionStart + rcRouteLength;

						// Pointer
						var rcRoutePointerByte = packet.GetByteList().GetRange(34 + treatedOptionBytes, 1);
						treatedOptionBytes++;
						var rcRoutePointer = Convert.ToInt32(rcRoutePointerByte[0].ToString("X2"), 16);
						
						var ipList = new List<string>();
						var firstIpByte = 34 + treatedOptionBytes;
						
						// IP List
						while (34 + treatedOptionBytes < optionEnd)
						{
							var recordRouteIpBytes = packet.GetByteList().GetRange(34 + treatedOptionBytes, 4);
							ipList.Add(string.Join('.', recordRouteIpBytes.Select(b => b.ToString())));
							treatedOptionBytes += 4;
						}
						
						// Build ByteRange

						// Parent ByteRange
						lastIndex = ModelHelper.ByteShifter(lastIndex, data, rcRouteLength);
						var rcRouteRange = new ByteRange("Record Route", rangeStart, lastIndex, 
							packet.GetByteList().GetRange(optionStart, rcRouteLength), $"Record Route ({rcRouteLength} bytes)");
						

						// Type ByteRange
						var oTypeRange = new ByteRange("Type", rangeStart, 
							ModelHelper.ByteShifter(rangeStart, data, 1), optionTypeByte, $"{ToHexRepresentation(optionTypeByte)} ({optionType})");

						// Length ByteRange
						var oLengthRange = new ByteRange("Length", oTypeRange.GetRangeEnd(), 
							ModelHelper.ByteShifter(oTypeRange.GetRangeEnd(), data, 1), rcRouteLengthByte, rcRouteLength.ToString());

						// Pointer ByteRange
						var oPointerRange = new ByteRange("Pointer", oLengthRange.GetRangeEnd(), 
							ModelHelper.ByteShifter(oLengthRange.GetRangeEnd(), data, 1), rcRoutePointerByte, rcRoutePointer.ToString());
						
						// Add option parameters to parent
						rcRouteRange.AddChild(oTypeRange);
						rcRouteRange.AddChild(oLengthRange);
						rcRouteRange.AddChild(oPointerRange);

						rangeStart = oPointerRange.GetRangeEnd();
						foreach (var ip in ipList)
						{
							lastIndex = ModelHelper.ByteShifter(rangeStart, data, 4);
							rcRouteRange.AddChild(new ByteRange("Recorded Route", rangeStart, lastIndex,
								packet.GetByteList().GetRange(firstIpByte, 4), ip));
							rangeStart = lastIndex;
							firstIpByte += 4;
						}
						
						optionsRange.AddChild(rcRouteRange);
						break;
				}
			}

			if (headerLength != treatedBytes + treatedOptionBytes)
			{
				throw new FormatException(
					$"Header length ({headerLength}) did not coincide with End of Options List (Found at byte {treatedBytes + treatedOptionBytes}).");
			}
			
			ipv4.AddChild(optionsRange);
			
			return ipv4;
		}

		public static ByteRange ParseTcp(ByteRange packet, string data, int offset, int startIndex)
		{
			// Source Port
			var srcPortBytes = packet.GetByteList().GetRange(offset, 2);
			var srcPort = Convert.ToInt32(string.Join("", srcPortBytes.Select(b => b.ToString("X2"))), 16);
			
			// Destination Port
			var dstPortBytes = packet.GetByteList().GetRange(offset + 2, 2);
			var dstPort = Convert.ToInt32(string.Join("", dstPortBytes.Select(b => b.ToString("X2"))), 16);

			// Sequence Number
			var seqBytes = packet.GetByteList().GetRange(offset + 4, 4);
			var seq = Convert.ToInt32(string.Join("", seqBytes.Select(b => b.ToString("X2"))), 16);
			
			// Acknowledgement Number
			var ackBytes = packet.GetByteList().GetRange(offset + 8, 4);
			var ack = Convert.ToInt32(string.Join("", ackBytes.Select(b => b.ToString("X2"))), 16);
			
			var firstByteAsList = new List<byte>() {packet.GetByteList()[offset + 12]};
			var first = packet.GetByteList()[offset + 12].ToString("X2");

			// Header Length
			var headerBytes = first.Substring(0,1);
			var headerLength = Convert.ToInt32(headerBytes, 16) * 4;
			
			// Flags
			var flagBytes = packet.GetByteList().GetRange(offset + 12, 2);
			var flagsStr = ToHexRepresentation(flagBytes);
			flagsStr = flagsStr.Substring(3, 3);
			var frag = Convert.ToString(
				Convert.ToInt32(flagsStr, 16), 2).PadLeft(16,'0');

			var reserved = Convert.ToInt32(frag.Substring(4,3));
			var nonce = Convert.ToInt32(frag.Substring(7,1));
			var cwr = Convert.ToInt32(frag.Substring(8,1));
			var ecnecho = Convert.ToInt32(frag.Substring(9,1));
			var urgent = Convert.ToInt32(frag.Substring(10,1));
			var acknowledgement = Convert.ToInt32(frag.Substring(11,1));
			var push = Convert.ToInt32(frag.Substring(12,1));
			var reset = Convert.ToInt32(frag.Substring(13,1));
			var syn = Convert.ToInt32(frag.Substring(14,1));
			var fin = Convert.ToInt32(frag.Substring(15,1));
			
			// Window
			var winBytes = packet.GetByteList().GetRange(offset + 14, 2);
			var window = Convert.ToInt32(string.Join("", winBytes.Select(b => b.ToString("X2"))), 16);
			
			// Checksum
			var checksumBytes = packet.GetByteList().GetRange(offset + 16, 2);
			var checksum = ToHexRepresentation(checksumBytes);
			
			// Urgent
			var urgentBytes = packet.GetByteList().GetRange(offset + 18, 2);
			var urgentPointer = Convert.ToInt32(string.Join("", urgentBytes.Select(b => b.ToString("X2"))), 16);
			
			// Make ByteRanges

			var cursor = ModelHelper.CursorSetter(startIndex, data);
			
			var tcp = new ByteRange("TCP", cursor, ModelHelper.ByteShifter(cursor, data, headerLength), 
				packet.GetByteList().GetRange(startIndex,headerLength), $"Src Port: {srcPort} Dst Port: {dstPort}, Seq: {seq}, Ack: {ack}");
			
			var srcPortRange = new ByteRange("Source Port", cursor, ModelHelper.ByteShifter(cursor, data, 2), 
				srcPortBytes, srcPort.ToString());
			tcp.AddChild(srcPortRange);
			
			var dstPortRange = new ByteRange("Destination Port", srcPortRange.GetRangeEnd(), 
				ModelHelper.ByteShifter(srcPortRange.GetRangeEnd(), data, 2), dstPortBytes, dstPort.ToString());
			tcp.AddChild(dstPortRange);
			
			var seqRange = new ByteRange("Sequence Number", dstPortRange.GetRangeEnd(), 
				ModelHelper.ByteShifter(dstPortRange.GetRangeEnd(), data, 4), seqBytes, seq.ToString());
			tcp.AddChild(seqRange);
			
			var ackRange = new ByteRange("Acknowledgment Number", seqRange.GetRangeEnd(), 
				ModelHelper.ByteShifter(seqRange.GetRangeEnd(), data, 4), ackBytes, ack.ToString());
			tcp.AddChild(ackRange);
			
			var ihlRange = new ByteRange("Header Length", ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 1),
				firstByteAsList, $"{headerLength.ToString()} bytes ({Convert.ToInt32(headerBytes, 16)})");
			tcp.AddChild(ihlRange);
			
			var flags = new ByteRange("Flags: ",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"0x{flagsStr}");
			tcp.AddChild(flags);

			var reservedFlagRange = new ByteRange($"000. .... ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Reserved Bit: Not set");
			flags.AddChild(reservedFlagRange);

			var nonceRange = new ByteRange($"...{nonce} .... ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Nonce: {(nonce == 1 ? "Set" : "Not set")}");
			flags.AddChild(nonceRange);

			var cwrRange = new ByteRange($".... {cwr}... ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Congestion Window Reduced: {(cwr == 1 ? "Set" : "Not set")}");
			flags.AddChild(cwrRange);

			var ecnechoRange = new ByteRange($".... .{ecnecho}.. ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"ECN-Echo: {(ecnecho == 1 ? "Set" : "Not set")}");
			flags.AddChild(ecnechoRange);

			var urgentRange = new ByteRange($".... ..{urgent}. ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Urgent: {(urgent == 1 ? "Set" : "Not set")}");
			flags.AddChild(urgentRange);

			var ackFlagRange = new ByteRange($".... ...{acknowledgement} ....",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Acknowledgment: {(acknowledgement == 1 ? "Set" : "Not set")}");
			flags.AddChild(ackFlagRange);
			
			var pushRange = new ByteRange($".... .... {push}...",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Push: {(push == 1 ? "Set" : "Not set")}");
			flags.AddChild(pushRange);

			var resetRange = new ByteRange($".... .... .{reset}..",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Reset: {(reset == 1 ? "Set" : "Not set")}");
			flags.AddChild(resetRange);

			var synRange = new ByteRange($".... .... ..{syn}. ",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Syn: {(syn == 1 ? "Set" : "Not set")}");
			flags.AddChild(synRange);

			var finRange = new ByteRange($".... .... ...{fin}",
				ackRange.GetRangeEnd(), ModelHelper.ByteShifter(ackRange.GetRangeEnd(), data, 2),
				flagBytes, $"Fin: {(fin == 1 ? "Set" : "Not set")}");
			flags.AddChild(finRange);
			
			var winRange = new ByteRange("Window Size Value", flags.GetRangeEnd(), ModelHelper.ByteShifter(flags.GetRangeEnd(), data, 2),
				winBytes, $"{ToHexRepresentation(winBytes)} ({window})");
			tcp.AddChild(winRange);
			
			var checksumRange = new ByteRange("Checksum",
				winRange.GetRangeEnd(), ModelHelper.ByteShifter(winRange.GetRangeEnd(), data, 2),
				checksumBytes, checksum);
			tcp.AddChild(checksumRange);
			
			var urgpoRange = new ByteRange("Urgent Pointer", checksumRange.GetRangeEnd(), ModelHelper.ByteShifter(checksumRange.GetRangeEnd(), data, 2),
				urgentBytes, $"{ToHexRepresentation(urgentBytes)} ({urgentPointer})");
			tcp.AddChild(urgpoRange);

			
			// Options

			return tcp;
		}

		public static IList<string> Format(string data)
		{
			// Split text file into a list of lines
			var lines = data.Split(new[] {"\r\n", "\r", "\n"}, StringSplitOptions.None).ToList();
			// Result to return
			var formattedLines = new List<string>();
			
			// Remove all lines that are empty or show no byte representation
			lines.RemoveAll(string.IsNullOrWhiteSpace);
			lines.RemoveAll(str => str.Split(' ').All(b => !IsByteRepresentation(b)));

			for(var i = 0; i < lines.Count; i++)
			{
				// Split each word, while removing excess whitespaces
				var sList = lines[i].Split(' ').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
				try
				{
					// Check for offset, first word must be a hex number, throws an exception otherwise
					var offset = Convert.ToInt32(sList[0], 16);
					
					// Number of bytes that must be added
					// If current line isn't the last one, check next line's offset to find
					// how many bytes the line is supposed to contain
					var bytesToAdd = sList.Count(IsByteRepresentation);
					if (i != lines.Count - 1)
					{
						if (Convert.ToInt32(lines[i + 1].Split(' ').ToArray()[0], 16) != 0)
						{
							var nextOffset = Convert.ToInt32(lines[i + 1].Split(' ').ToArray()[0], 16);
							bytesToAdd = nextOffset - offset;
						}
					}
					
					// Remove offset from string to see
					var strOffset = sList[0];
					var fLine = sList.GetRange(1, bytesToAdd).Where(IsByteRepresentation).ToList();
					if(fLine.Count != bytesToAdd) 
						throw new FormatException($"Line {i + 1} of file was malformatted: Expected {bytesToAdd} bytes, got {fLine.Count}");

					fLine.Insert(0, strOffset);
					formattedLines.Add(string.Join(" ", fLine));
				}
				catch (Exception e)
				{
					// Line is not formatted as part of trace, ignoring...
					Console.WriteLine($"Part of file was ignored: {e}");
				}
			}

			return formattedLines;
		}

		/// <summary>
		/// Checks if a given string is a representation of a single byte.
		/// </summary>
		/// <param name="str"> String to check if readable as a byte </param>
		/// <returns>true if 2 characters long and made of hexadecimal characters, false otherwise</returns>
		private static bool IsByteRepresentation(string str)
		{
			return System.Text.RegularExpressions.Regex.IsMatch(str, @"\A\b[0-9a-fA-F]+\b\Z") && str.Length == 2;
		}
		private static string ToHexRepresentation(List<byte> bytes)
		{
			return "0x" + string.Join("", bytes.Select(b => b.ToString("X2")));
		}
	}
}