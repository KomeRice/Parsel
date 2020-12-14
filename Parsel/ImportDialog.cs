using System;
using Gtk;
using UI = Gtk.Builder.ObjectAttribute;
using Window = Gtk.Window;
#pragma warning disable 414

namespace Parsel
{
	public class ImportDialog : Dialog
	{
		[UI] private Button _buttonImport = null;
		[UI] private TextView _importText = null;

		public ImportDialog() : this(new Builder("ImportDialog.glade"))
		{
		}

		private ImportDialog(Builder builder) : base(builder.GetObject("ImportDialog").Handle)
		{
			
			builder.Autoconnect(this);

			_importText.Buffer.Changed += TextChanged;
		}

		public string GetBufferText()
		{
			return _importText.Buffer.Text;
		}

		private void TextChanged(object sender, EventArgs a)
		{
			_buttonImport.Sensitive = _importText.Buffer.Text.Length > 0;
		}
	}
}