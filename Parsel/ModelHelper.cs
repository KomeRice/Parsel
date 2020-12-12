using System;
using System.Collections.Generic;
using Gtk;

namespace Parsel
{
	public static class ModelHelper
	{
		public static void AddChildren(ByteRange byteRange, TreeStore treeStore, TreeIter parentIter, List<ByteRange> allNodes)
		{
			
			var child = treeStore.AppendValues(parentIter, byteRange.GetField(), byteRange.GetByteList().Count,
				byteRange.GetValue(), byteRange.GetId());
			allNodes.Add(byteRange);
			foreach (var grandchild in byteRange.GetChildren())
			{
				AddChildren(grandchild, treeStore, child, allNodes);
			}
		}

		public static void ByteHighlighter(int firstIndex, int nbBytesToHighlight, TextTag highlight, TextBuffer buffer)
		{
			var csr = firstIndex;
			var str = buffer.Text.Substring(csr, buffer.Text.Length - csr);

			for(var toHighlight = nbBytesToHighlight; toHighlight != 0; toHighlight--)
			{
				// New line, ignore offset
				csr = CursorSetter(csr, buffer.Text);
				var iterStart = buffer.GetIterAtOffset(csr);
				var iterEnd = buffer.GetIterAtOffset(csr + 3);
				csr += 3;
				buffer.ApplyTag(highlight, iterStart, iterEnd);
			}
		}

		public static int CursorSetter(int csr, string data)
		{
			var nCursor = csr;
			// New line, ignore offset
			if (csr == 0 || data.Substring(csr, 1).Equals("\n")
			             || data.Substring(csr - 1, 1).Equals("\n"))
			{
				nCursor = data.IndexOf(" ", csr, StringComparison.Ordinal) + 1;
				if(csr >= data.Length) throw new IndexOutOfRangeException("Attempted to access bytes after EOF");
			}

			return nCursor;
		}
		
		public static int ByteShifter(int csr, string data, int shift)
		{
			for (var i = 0; i < shift; i++)
			{
				csr = CursorSetter(csr, data);
				csr += 3;
			}

			return csr;
		}
	}
}