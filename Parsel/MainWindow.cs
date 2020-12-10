using System;
using System.IO;
using System.Security.Cryptography;
using Gdk;
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
		[UI] private ListStore _traceTree = null;

		public MainWindow() : this(new Builder("MainWindow.glade"))
		{
		}

		private MainWindow(Builder builder) : base(builder.GetObject("MainWindow").Handle)
		{
			builder.Autoconnect(this);

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
				_printTrace.Buffer.Text = f;
				var index = f.IndexOf("AMD", StringComparison.Ordinal);
				TextTag hl = new TextTag("Highlight")
				{
					Background = "#0000ff",
					Foreground = "white",
					Weight = Weight.Bold
				};

				_traceBuffer.TagTable.Add(hl);
				
				var iter1 = _traceBuffer.GetIterAtOffset(index);
				var iter2 = _traceBuffer.GetIterAtOffset(index + 3);
				
				Application.Invoke(delegate
				{
					_traceBuffer.ApplyTag(hl, iter1, iter2);
				});
			}
			else
			{
				fc.Dispose();
			}
		}
	}
}