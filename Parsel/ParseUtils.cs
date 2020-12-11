using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Parsel
{
	public static class ParseUtils
	{
		public static IEnumerable<ByteRange> Parse(IList<string> fData)
		{
			var parsedBytes = new List<ByteRange>();

			// Split Packets

			var startPacketIndex = 0;
			var endIndex = 0;
			var packetNumber = 0;
			var byteList = new List<byte>();
			
			for(var i = 0; i < fData.Count; i++)
			{
				var offset = Convert.ToInt32(fData[i].Split(' ').ToArray()[0], 16);
				if (offset == 0 && startPacketIndex != endIndex)
				{
					parsedBytes.Add(new ByteRange($"Packet {packetNumber}", startPacketIndex, endIndex, byteList));
					packetNumber += 1;
					startPacketIndex = endIndex;
					byteList = new List<byte>();
				}
				var strBytes = fData[i].Split(' ').ToList();
				if (!fData[i].Equals(fData.Last()) && Convert.ToInt32(fData[i + 1].Split(' ').ToArray()[0], 16) != 0)
				{
					var nextOffset = Convert.ToInt32(fData[i + 1].Split(' ').ToArray()[0], 16);
					var bytesToAdd = nextOffset - offset;
					var addBytes = strBytes.GetRange(1, bytesToAdd).Select(b => Convert.ToByte(b, 16)).ToList();
					byteList.AddRange(addBytes);
					// Increment by two for newline escape character
					endIndex += string.Join(' ', strBytes.GetRange(0,bytesToAdd + 1)).Length + 1;
				}
				else
				{
					byteList.AddRange(strBytes.GetRange(1, strBytes.Count - 1).Select(b => Convert.ToByte(b, 16)));
					endIndex += fData[i].Length;
				}
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
					Console.WriteLine($"Part of file was ignored: {e.Message}");
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