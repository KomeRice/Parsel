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
					var root = _traceTree.AppendValues(packet.GetField(), packet.GetByteList().Count, "", packet.GetId());
					
					// Parse headers
					
					// Ethernet
					var ethernet = ParseUtils.ParseEthernet(packet, _traceBuffer.Text);
					packet.AddChild(ethernet);
					ModelHelper.AddChildren(ethernet, _traceTree, root, _byteRanges);

					var type = ethernet.GetChildren().Find(br => br.GetField() == "Type");
					if (type == null) return;
					if (!type.GetValue().Contains("IPv4")) return;
					
					// Ip
					var ip = ParseUtils.ParseIp(packet, _traceBuffer.Text);
					packet.AddChild(ip);
					ModelHelper.AddChildren(ip, _traceTree, root, _byteRanges);
					
					var protocol = ip.GetChildren().Find(br => br.GetField() == "Protocol");
					if (protocol == null) return;
					if (!protocol.GetValue().Contains("TCP")) return;

					var byteOffsetTcp = ip.GetByteList().Count + ethernet.GetByteList().Count;
					var startIndexTcp = ip.GetRangeEnd();
					
					//Tcp

					var tcp = ParseUtils.ParseTcp(packet, _traceBuffer.Text, byteOffsetTcp, startIndexTcp);
					packet.AddChild(tcp);
					ModelHelper.AddChildren(tcp, _traceTree, root, _byteRanges);

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
				var selectedId = Convert.ToInt32(model.GetValue(iter, 3).ToString());
				var selectedItem = _byteRanges.Find(b => b.GetId() == selectedId);
				Debug.Assert(selectedItem != null, nameof(selectedItem) + " != null");
				ModelHelper.ByteHighlighter(selectedItem.GetRangeStart(), selectedItem.GetByteList().Count, Highlight, _traceBuffer);
			}
		}
	}
}