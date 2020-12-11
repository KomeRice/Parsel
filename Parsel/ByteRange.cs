using System.Collections.Generic;

namespace Parsel
{
	public class ByteRange
	{
		private readonly string _fieldName;
		private readonly int _rangeStart, _rangeEnd;
		private readonly IList<byte> _byteList;
		private readonly ByteRange _parentHeader;

		public ByteRange(string fieldName, int start, int end, IList<byte> byteList, ByteRange parent = null)
		{
			_fieldName = fieldName;
			_rangeStart = start;
			_rangeEnd = end;
			_byteList = byteList;
			_parentHeader = parent;
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
		
		public IList<byte> GetByteList()
		{
			return _byteList;
		}
	}
}