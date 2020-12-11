using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Gtk;
using Pango;
using UI = Gtk.Builder.ObjectAttribute;
using Window = Gtk.Window;
// ReSharper disable FieldCanBeMadeReadOnly.Local

// Can be ignored because of Gtk generates UI elements
#pragma warning disable 414

namespace Parsel
{
	class MainWindow : Window
	{
		[UI] private Label _labelPrompt = null;
		[UI] private Button _buttonPickFile = null;
		
		[UI] private TextView _printTrace = null;
		[UI] private TreeView _displayTrace = null;
		[UI] private TextBuffer _traceBuffer = null;
		[UI] private TreeStore _traceTree = null;

		private static List<ByteRange> _byteRanges = new List<ByteRange>();

		private static readonly TextTag Highlight = new TextTag("Highlight")
		{
			Background = "#0000ff",
			Foreground = "white",
			Weight = Weight.Bold
		};

		public MainWindow() : this(new Builder("MainWindow.glade"))
		{
		}

		private MainWindow(Builder builder) : base(builder.GetObject("MainWindow").Handle)
		{
			builder.Autoconnect(this);
			
			_traceBuffer.TagTable.Add(Highlight);

			DeleteEvent += Window_DeleteEvent;
			_buttonPickFile.Clicked += FileClicked;
			_displayTrace.CursorChanged += TreeOnCursorChanged;
		}

		private void Window_DeleteEvent(object sender, DeleteEventArgs a)
		{
			Application.Quit();
		}

		private void FileClicked(object sender, EventArgs a)
		{
			var fc = new FileChooserDialog("Choisir fichier à ouvrir", this, 
				FileChooserAction.Open, "Annuler", ResponseType.Cancel, "Ouvrir", ResponseType.Accept);

			var filter = new FileFilter {Name = "Fichiers texte"};
			filter.AddPattern("*.txt");
			fc.Filter = filter;

			if (fc.Run() == (int) ResponseType.Accept)
			{
				// Read and format file
				var f = File.ReadAllText(fc.Filename);
				fc.Dispose();
				var formattedFile = ParseUtils.Format(f);
				_printTrace.Buffer.Text = string.Join("\n", formattedFile);
				
				// Split file into packets 
				var packets = ParseUtils.ParseFile(formattedFile).ToList();
				_byteRanges.AddRange(packets);
				// Parse packets and add to tree
				foreach(var packet in packets) {
					var root = _traceTree.AppendValues(packet.GetField(), packet.GetByteList().Count, "");
					
					// Parse headers
					ModelHelper.AddChildren(ParseUtils.ParseEthernet(packet), _traceTree, root, _byteRanges);
				}

			}
			else
			{
				fc.Dispose();
			}
		}

		private void TreeOnCursorChanged(object sender, EventArgs e)
		{
			_traceBuffer.RemoveAllTags(_traceBuffer.StartIter, _traceBuffer.EndIter);
			
			var selection = (sender as TreeView)?.Selection;

			if (selection != null && selection.GetSelected(out var model, out var iter))
			{
				var selectedItem = _byteRanges.Find(b => b.GetField().Equals(model.GetValue(iter, 0)));
				Debug.Assert(selectedItem != null, nameof(selectedItem) + " != null");
				var iterStart = _traceBuffer.GetIterAtOffset(selectedItem.GetRangeStart());
				var iterEnd = _traceBuffer.GetIterAtOffset(selectedItem.GetRangeEnd());
				_traceBuffer.ApplyTag(Highlight, iterStart, iterEnd);
			}
		}
	}
}