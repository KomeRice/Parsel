using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Parsel
{
	public static class ParseUtils
	{
		public static IEnumerable<ByteRange> Parse(IEnumerable<string> fData)
		{
			var parsedBytes = new List<ByteRange>();

			// Split Packets

			var startPacketIndex = 0;
			var endIndex = 0;
			var packetNumber = 0;
			var byteList = new List<byte>();
			
			foreach(var line in fData)
			{
				if (Convert.ToInt32(line.Split(' ').ToArray()[0],16) == 0 && startPacketIndex != endIndex)
				{
					
					parsedBytes.Add(new ByteRange($"Packet {packetNumber}", startPacketIndex, endIndex, byteList));
					packetNumber += 1;
					startPacketIndex = endIndex;
					byteList = new List<byte>();
				}
				var strBytes = line.Split(' ').ToList();
				byteList.AddRange(strBytes.GetRange(1, strBytes.Count - 1).Select(b => Convert.ToByte(b, 16))); 
				endIndex += line.Length;
			}
			parsedBytes.Add(new ByteRange($"Packet {packetNumber}", startPacketIndex, endIndex, byteList));

			
			return parsedBytes;
		}

		public static IEnumerable<string> Format(string data)
		{
			var lines = data.Split(new[] {"\r\n", "\r", "\n"}, StringSplitOptions.None);
			var formattedLines = new List<string>();

			foreach (var line in lines)
			{
				var sList = line.Split(' ').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
				try
				{
					// Check for offset, first word must be a hex number
					var cv = Convert.ToInt32(sList[0], 16);
					if (sList.Any(b => b.Length == 2 && IsHexRepresentation(b)))
					{
						var offset = sList[0];
						var fLine = new List<string>();
						foreach (var b in sList.GetRange(1, sList.Count - 1))
						{
							if(b.Length == 2 && IsHexRepresentation(b)) fLine.Add(b);
							else
							{
								break;
							}
						}
						fLine.Insert(0, offset);
						
						formattedLines.Add(string.Join(" ", fLine));
					}
				}
				catch (Exception e)
				{
					// Line is not formatted as part of trace, ignoring...
				}
			}

			return formattedLines;
		}

		private static bool IsHexRepresentation(string str)
		{
			return System.Text.RegularExpressions.Regex.IsMatch(str, @"\A\b[0-9a-fA-F]+\b\Z");
		}
	}
}