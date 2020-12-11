using System.Collections.Generic;
using Gtk;

namespace Parsel
{
	public static class ModelHelper
	{
		public static void AddChildren(ByteRange byteRange, TreeStore treeStore, TreeIter parentIter, List<ByteRange> allNodes)
		{
			
			var child = treeStore.AppendValues(parentIter, byteRange.GetField(), byteRange.GetByteList().Count,
				byteRange.GetValue());
			allNodes.Add(byteRange);
			foreach (var grandchild in byteRange.GetChildren())
			{
				AddChildren(grandchild, treeStore, child, allNodes);
			}
		}
	}
}