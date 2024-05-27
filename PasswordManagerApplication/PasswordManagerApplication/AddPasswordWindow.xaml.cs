
using System.Windows;

namespace PasswordManager
{
    /// <summary>
    /// Interaction logic for AddPasswordWindow.xaml
    /// </summary>
    public partial class AddPasswordWindow : Window
    {
        public AddPasswordWindow()
        {
            InitializeComponent();
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = true;
            this.Close();
        }
    }
}
