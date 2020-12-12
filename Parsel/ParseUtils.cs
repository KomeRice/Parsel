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
			var typeRange = new ByteRange($"Type", dstIpRange.GetRangeEnd() + 18,
				ModelHelper.ByteShifter(srcIpRange.GetRangeEnd(), data, 2), typeBytes, type);
			
			ethernetLayer.AddChild(typeRange);
			ethernetLayer.AddChild(dstIpRange);
			ethernetLayer.AddChild(srcIpRange);

			return ethernetLayer;
			
			
		}

		public static ByteRange ParseIp(ByteRange packet, string data)
		{
			// ModelHelper.CursorSetter(packet.GetRangeStart(), data) + 48
			
			// Version
			var firstByteAsList = new List<byte>() {packet.GetByteList()[14]};
			var first = packet.GetByteList()[14].ToString("X2");
			var version = Convert.ToInt32(first.Substring(0,1), 16);

			// Header Length
			var headerBytes = first.Substring(1,1);
			var headerLength = Convert.ToInt32(headerBytes, 16) * 4;
			
			// Type of service
			var tos = packet.GetByteList()[15].ToString("X2");
			
			// Total Length
			var tLengthBytes = packet.GetByteList().GetRange(16, 2);
			var totalLength = Convert.ToInt32(string.Join("", tLengthBytes.Select(b => b.ToString("X2"))), 16);
			
			// Identification
			var identificationBytes = packet.GetByteList().GetRange(18, 2);
			var identification = "0x" + string.Join("", identificationBytes.Select(b => b.ToString("X2")));
			
			// Fragmentation
			var fragBytes = packet.GetByteList().GetRange(20, 2);
			var frag = ToBinaryWord(Convert.ToInt32(string.Join("", fragBytes.Select(b => b.ToString("X2")))),16);
			var flagsStr = "0x" + string.Join("", fragBytes.Select(b => b.ToString("X2")));

			
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
			var checksum = "0x" + string.Join("", checksumBytes.Select(b => b.ToString("X2")));
			
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
				firstByteAsList, $"Header Length: {headerLength.ToString()}");
			ipv4.AddChild(ihlRange);

			var tosRange = new ByteRange("Type of service", ihlRange.GetRangeEnd(), ModelHelper.ByteShifter(ihlRange.GetRangeEnd(), data, 1),
				new List<byte>() {packet.GetByteList()[15]}, $"Type of service: {tos}");
			ipv4.AddChild(tosRange);

			var totalLengthRange = new ByteRange("Total Length", 
				tosRange.GetRangeEnd(), ModelHelper.ByteShifter(tosRange.GetRangeEnd(), data, 2),
				tLengthBytes,$"Total Length: {totalLength} bytes");
			ipv4.AddChild(totalLengthRange);

			var identificationRange = new ByteRange("Identification",
				totalLengthRange.GetRangeEnd(), ModelHelper.ByteShifter(totalLengthRange.GetRangeEnd(), data, 2),
				identificationBytes, $"Identification: {identification}");
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
				ttlByte, ttl.ToString());
			ipv4.AddChild(ttlRange);

			var protocolRange = new ByteRange("Protocol",
				ttlRange.GetRangeEnd(), ModelHelper.ByteShifter(ttlRange.GetRangeEnd(), data, 1),
				protocolBytes, $"{protocol} ({protocolStr})");
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
			
			return ipv4;
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
		
		public static string ToBinaryWord(int value, int len) {
			return (len > 1 ? ToBinaryWord(value >> 1, len - 1) : null) + "01"[value & 1];
		}
	}
}