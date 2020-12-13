using System.Collections.Generic;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Parsel
{
	/// <summary>
	/// Allows the representation and display of information based on byte parsing
	/// </summary>
	public class ByteRange
	{
		/// <summary>
		/// Internal modifier counting byterange for indexing
		/// </summary>
		private static int _count = 0;
		/// <summary>
		/// Unique identifier of byterange
		/// </summary>
		private readonly int _id;
		/// <summary>
		/// ByteRange title
		/// </summary>
		[JsonProperty(PropertyName = "Field")]
		private readonly string _fieldName;
		/// <summary>
		/// ByteRange value
		/// </summary>
		[JsonProperty(PropertyName = "Value")]
		private readonly string _value;
		/// <summary>
		/// Start or end of ByteRange in displayed data
		/// </summary>
		private readonly int _rangeStart, _rangeEnd;
		/// <summary>
		/// List of bytes contained in this ByteRange
		/// </summary>
		private readonly List<byte> _byteList;
		/// <summary>
		/// Parent ByteRange if exists, null otherwise
		/// </summary>
		private ByteRange _parentHeader;
		/// <summary>
		/// Size in bytes of ByteRange
		/// </summary>
		[JsonProperty(PropertyName = "Size")]
		private int _size;
		/// <summary>
		/// Children ByteRanges of this ByteRange
		/// </summary>
		[JsonProperty(PropertyName = "Children")]
		private List<ByteRange> _children = new List<ByteRange>();
		

		/// <summary>
		/// Creates a ByteRange representing data in a trace
		/// </summary>
		/// <param name="fieldName">Title of represented data</param>
		/// <param name="start">Index of the first byte in raw trace</param>
		/// <param name="end">Index of the end of the last byte in raw trace</param>
		/// <param name="byteList">List of bytes represented</param>
		/// <param name="value">String representation of this ByteRange's data, empty if not supplied</param>
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
		
		/// <summary>
		/// Gets the string representation of this ByteRange's data
		/// </summary>
		/// <returns>String representation of this ByteRange's data</returns>
		public string GetValue()
		{
			return _value;
		}

		/// <summary>
		/// Gets the index of the first byte's first character in raw trace
		/// </summary>
		/// <returns>Index of the start of the first byte in raw trace</returns>
		public int GetRangeStart()
		{
			return _rangeStart;
		}
		
		/// <summary>
		/// Gets the index of the last byte's last character in raw trace
		/// </summary>
		/// <returns>Index of the end of the last byte in raw trace</returns>
		public int GetRangeEnd()
		{
			return _rangeEnd;
		}
		
		/// <summary>
		/// Gets the title of this ByteRange
		/// </summary>
		/// <returns>This ByteRange's title</returns>
		public string GetField()
		{
			return _fieldName;
		}
		
		/// <summary>
		/// Gets the list of bytes represented by this ByteRange
		/// </summary>
		/// <returns>List of bytes represented by this ByteRange</returns>
		public List<byte> GetByteList()
		{
			return _byteList;
		}

		/// <summary>
		/// Gets the children ByteRanges of this ByteRange
		/// </summary>
		/// <returns>Children ByteRanges of this ByteRange as a list</returns>
		public List<ByteRange> GetChildren()
		{
			return _children;
		}
		
		/// <summary>
		/// Gets the amount of bytes contained in this ByteRange
		/// </summary>
		/// <returns>Size of GetByteList()</returns>
		public int GetSize()
		{
			return _size;
		}

		/// <summary>
		/// Sets a parent to this ByteRange
		/// </summary>
		/// <param name="parent">Parent of this ByteRange</param>
		private void SetAsChildren(ByteRange parent)
		{
			_parentHeader = parent;
			parent._children.Add(this);
		}

		/// <summary>
		/// Adds a ByteRange as a child element of this byterange and sets this byterange as child's parent
		/// </summary>
		/// <param name="child">ByteRange to add as child</param>
		public void AddChild(ByteRange child)
		{
			child.SetAsChildren(this);
		}

		/// <summary>
		/// Gets the unique identifier of this ByteRange
		/// </summary>
		/// <returns>Unique identifier of ByteRange</returns>
		public int GetId()
		{
			return _id;
		}
		
		// Tells Serializer to only export if not empty
		public bool ShouldSerialize_fieldName()
		{
			return _fieldName.Length > 0;
		}

		// Tells Serializer to only export if not empty
		public bool ShouldSerialize_value()
		{
			return _value.Length > 0;
		}

		// Tells Serializer to only export if not empty
		public bool ShouldSerialize_children()
		{
			return _children.Count > 0;
		}

		/// <summary>
		/// Translates a ByteRange into a JSON object, only keeping field name, size, value and children elements.
		/// This should only be called from a root element.
		/// </summary>
		/// <returns>JSON String of this ByteRange</returns>
		public string ToJson()
		{
			return JsonConvert.SerializeObject(this, Formatting.Indented);
		}

		/// <summary>
		/// Resets the global count on ByteRanges, should only be called if a new file is being read
		/// </summary>
		public static void ResetCount()
		{
			_count = 0;
		}
	}
}