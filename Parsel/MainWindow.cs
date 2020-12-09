using System;
using System.IO;
using System.Security.Cryptography;
using Gtk;
using UI = Gtk.Builder.ObjectAttribute;

// Can be ignored because of Gtk generates UI elements
#pragma warning disable 414

namespace Parsel
{
	class MainWindow : Window
	{
		[UI] private Label _label = null;
		[UI] private readonly Button _pickButton = null;

		public MainWindow() : this(new Builder("MainWindow.glade"))
		{
		}

		private MainWindow(Builder builder) : base(builder.GetObject("MainWindow").Handle)
		{
			builder.Autoconnect(this);

			DeleteEvent += Window_DeleteEvent;
			_pickButton.Clicked += Button_Clicked;
		}

		private void Window_DeleteEvent(object sender, DeleteEventArgs a)
		{
			Application.Quit();
		}

		private void Button_Clicked(object sender, EventArgs a)
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
			}
			else
			{
				fc.Dispose();
			}
		}
	}
}