using System.Collections.Generic;

namespace Parsel
{
	public class ByteRange
	{
		private static int Count = 0;
		private readonly int _id;
		private readonly string _fieldName;
		private readonly string _value;
		private readonly int _rangeStart, _rangeEnd;
		private readonly List<byte> _byteList;
		private ByteRange _parentHeader;
		private List<ByteRange> _children = new List<ByteRange>();

		public ByteRange(string fieldName, int start, int end, List<byte> byteList,string value = "")
		{
			_id = Count;
			++Count;
			_fieldName = fieldName;
			_rangeStart = start;
			_rangeEnd = end;
			_byteList = byteList;
			_value = value;
		}

		public string GetValue()
		{
			return _value;
		}

		public int GetRangeStart()
		{
			return _rangeStart;
		}
		
		public int GetRangeEnd()
		{
			return _rangeEnd;
		}
		
		public string GetField()
		{
			return _fieldName;
		}
		
		public List<byte> GetByteList()
		{
			return _byteList;
		}

		public List<ByteRange> GetChildren()
		{
			return _children;
		}

		private void SetAsChildren(ByteRange parent)
		{
			_parentHeader = parent;
			parent._children.Add(this);
		}

		public void AddChild(ByteRange child)
		{
			child.SetAsChildren(this);
		}

		public int GetId()
		{
			return _id;
		}
	}
}