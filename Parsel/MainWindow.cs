using System;
using System.IO;
using System.Security.Cryptography;
using Gdk;
using Gtk;
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

			if (fc.Run() == (int) ResponseType.Accept)
			{
				var f = File.OpenRead(fc.Filename);
				var hash = MD5.Create();
				var hashValue = BitConverter.ToString(hash.ComputeHash(f));
				var messageDialog = new MessageDialog(this,DialogFlags.DestroyWithParent,MessageType.Info,
					ButtonsType.Close,$"Computed hash of {fc.File.Basename} is:\n{hashValue}");
				f.Close();
				fc.Dispose();
				messageDialog.Run();
				messageDialog.Dispose();
				TextTag hl = new TextTag("Highlight")
				{
					BackgroundRgba = new RGBA()
					{
						Red = 0,
						Green = 0,
						Blue = 255,
						Alpha = 1
					},
					ForegroundRgba = new RGBA()
					{
						Red = 255,
						Green = 255,
						Blue = 255,
						Alpha = 1
					}
				};
			}
			else
			{
				fc.Dispose();
			}
		}
	}
}