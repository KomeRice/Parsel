using System;
using System.IO;
using System.Linq;
using Gtk;
using Pango;
using UI = Gtk.Builder.ObjectAttribute;
using Window = Gtk.Window;

// Can be ignored because of Gtk generates UI elements
#pragma warning disable 414

namespace Parsel
{
	class MainWindow : Window
	{
		[UI] private Label _labelPrompt = null;
		[UI] private readonly Button _buttonPickFile = null;
		
		[UI] private TextView _printTrace = null;
		[UI] private TreeView _displayTrace = null;
		[UI] private TextBuffer _traceBuffer = null;
		[UI] private TreeStore _traceTree = null;
		
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
		}

		private void Window_DeleteEvent(object sender, DeleteEventArgs a)
		{
			Application.Quit();
		}

		private void FileClicked(object sender, EventArgs a)
		{
			var fc = new FileChooserDialog("Choose file to open", this, 
				FileChooserAction.Open, "Cancel", ResponseType.Cancel, "Open", ResponseType.Accept);

			var filter = new FileFilter {Name = "Fichiers texte"};
			filter.AddPattern("*.txt");
			fc.Filter = filter;

			if (fc.Run() == (int) ResponseType.Accept)
			{
				var f = File.ReadAllText(fc.Filename);
				fc.Dispose();
				var formattedFile = ParseUtils.Format(f).ToList();
				_printTrace.Buffer.Text = string.Join("\n", formattedFile);
				
				var packets = ParseUtils.Parse(formattedFile);
				foreach(var packet in packets) {
					var iter = _traceTree.AppendValues (packet.GetField(), packet.GetRangeStart(), packet.GetByteList().Count);
				}

				var index = f.IndexOf("AMD", StringComparison.Ordinal);
				
				
				var iter1 = _traceBuffer.GetIterAtOffset(index);
				var iter2 = _traceBuffer.GetIterAtOffset(index + 3);
				
				_traceBuffer.ApplyTag(Highlight, iter1, iter2);
				
			}
			else
			{
				fc.Dispose();
			}
		}
	}
}