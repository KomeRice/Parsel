using System;
using System.Collections.Generic;
using Gtk;

namespace Parsel
{
	/// <summary>
	/// Contains tools to assist with Viewmodel / Modelview treatment
	/// </summary>
	public static class ModelHelper
	{
		/// <summary>
		/// Adds a ByteRange and all its children to a treeview as well as to a list in order to find them when selected.
		/// </summary>
		/// <param name="byteRange">Parent ByteRange to add along with its children</param>
		/// <param name="treeStore">TreeStore to which the ByteRanges should be added to</param>
		/// <param name="parentIter">Iterator of root node</param>
		/// <param name="allNodes">List containing TreeStore's Byte Ranges</param>
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

		/// <summary>
		/// Applies a highlight to bytes in a buffer, skipping offsets.
		/// </summary>
		/// <param name="firstIndex">Index of first character to highlight</param>
		/// <param name="nbBytesToHighlight">Number of bytes to highlight</param>
		/// <param name="highlight">Highlight that should be applied to bytes</param>
		/// <param name="buffer">Buffer holding the raw trace data</param>
		public static void ByteHighlighter(int firstIndex, int nbBytesToHighlight, TextTag highlight, TextBuffer buffer)
		{
			var csr = firstIndex;

			for(var toHighlight = nbBytesToHighlight; toHighlight != 0; toHighlight--)
			{
				// New line, ignore offset
				csr = CursorSetter(csr, buffer.Text);
				if (csr == -1) return;
				var iterStart = buffer.GetIterAtOffset(csr);
				var iterEnd = buffer.GetIterAtOffset(csr + 3);
				csr += 3;
				buffer.ApplyTag(highlight, iterStart, iterEnd);
			}
		}

		/// <summary>
		/// Tries to position cursors at the start of the next valid byte, skipping offsets
		/// </summary>
		/// <param name="csr">Cursor to position</param>
		/// <param name="data">Data where the cursor is placed</param>
		/// <returns>New cursor at next byte's start from given cursor</returns>
		/// <exception cref="IndexOutOfRangeException">Thrown if the cursor goes out of the data's bounds</exception>
		public static int CursorSetter(int csr, string data)
		{
			var nCursor = csr;
			// New line, ignore offset
			if (csr != 0 && !data.Substring(csr, 1).Equals("\n") && !data.Substring(csr - 1, 1).Equals("\n"))
				return nCursor;
			try
			{
				nCursor = data.IndexOf(" ", csr, StringComparison.Ordinal) + 1;
				if (csr > data.Length) throw new IndexOutOfRangeException("Attempted to access bytes after EOF");

				return nCursor;
			}
			catch (Exception e)
			{
				Console.Error.WriteLine(e);
				return -1;
			}
		}
		
		/// <summary>
		/// Shifts a cursor by a given amount of bytes in data
		/// </summary>
		/// <param name="csr">Cursor to shift</param>
		/// <param name="data">Data where the cursor is placed</param>
		/// <param name="shift">Bytes by which the cursor should be shifted</param>
		/// <returns>Cursor shifted by given amount of bytes</returns>
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