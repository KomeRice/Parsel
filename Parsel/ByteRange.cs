using System.Collections.Generic;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Parsel
{
	public class ByteRange
	{
		private static int _count = 0;
		private readonly int _id;
		[JsonProperty(PropertyName = "Field")]
		private readonly string _fieldName;
		[JsonProperty(PropertyName = "Value")]
		private readonly string _value;
		private readonly int _rangeStart, _rangeEnd;
		private readonly List<byte> _byteList;
		private ByteRange _parentHeader;
		[JsonProperty(PropertyName = "Size")]
		private int _size;
		[JsonProperty(PropertyName = "Children")]
		private List<ByteRange> _children = new List<ByteRange>();
		

		public ByteRange(string fieldName, int start, int end, List<byte> byteList,string value = "")
		{
			_id = _count;
			++_count;
			_fieldName = fieldName;
			_rangeStart = start;
			_rangeEnd = end;
			_byteList = byteList;
			_value = value;
			_size = _byteList.Count;
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
		
		public int GetSize()
		{
			return _size;
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
		
		public bool ShouldSerialize_fieldName()
		{
			return _fieldName.Length > 0;
		}

		public bool ShouldSerialize_value()
		{
			return _value.Length > 0;
		}

		public bool ShouldSerialize_children()
		{
			return _children.Count > 0;
		}

		public string ToJson()
		{
			return JsonConvert.SerializeObject(this, Formatting.Indented);
		}
	}
}