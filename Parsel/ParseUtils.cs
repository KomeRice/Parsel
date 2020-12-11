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

		public static ByteRange ParseEthernet(ByteRange packet)
		{
			var ethernet = new List<ByteRange>();
			
			// Ethernet Parsing
			
			// Destination IP
			var dstIpBytes = packet.GetByteList().GetRange(0, 6);
			var srcIpBytes = packet.GetByteList().GetRange(6, 6);
			var typeBytes = packet.GetByteList().GetRange(12, 2);
			
			
			var dstIp = string.Join(':', dstIpBytes.Select(b => b.ToString("X2")));
			var srcIp = string.Join(':', srcIpBytes.Select(b => b.ToString("X2")));
			var typeStr = string.Join("", typeBytes.Select(b => b.ToString("X2")));
			var type = Convert.ToInt32(typeStr, 16) switch
			{
				2048 => "IPv4",
				2054 => "ARP",
				34525 => "IPv6",
				_ => "Unsupported"
			};
			type += $" (0x{typeStr})";
			
			var ethernetLayer = 
				new ByteRange("Ethernet II", 0,13,packet.GetByteList().GetRange(0,14),
					$"Src: {srcIp}, Dst: {dstIp}, Type: {type}");
			var typeRange = new ByteRange($"Type", 12,15, typeBytes, type);
			var dstIpRange = new ByteRange("Dst IP", 0, 5, dstIpBytes, dstIp);
			var srcIpRange = new ByteRange("Src IP", 6, 11, srcIpBytes, srcIp);
			
			ethernetLayer.AddChild(typeRange);
			ethernetLayer.AddChild(dstIpRange);
			ethernetLayer.AddChild(srcIpRange);

			return ethernetLayer;
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
	}
}