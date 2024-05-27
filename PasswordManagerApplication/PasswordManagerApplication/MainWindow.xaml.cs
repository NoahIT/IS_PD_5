using PasswordManager;
using System.Windows;
using System.Windows.Controls;
using PasswordManagerApplication.Auth;
using PasswordManagerApplication.AES;
using System.Security.Cryptography;
using System.IO;

namespace PasswordManagerApplication
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        public class PasswordEntry
        {
            public string ?Title { get; set; }
            public string ?EncryptedPassword { get; set; }
            public string ?Url { get; set; }
            public string ?Comment { get; set; }
            public string DecryptedPassword { get; set; } = string.Empty;
        }

        private void LoadAllPasswordsButton_Click(object sender, RoutedEventArgs e)
        {
            string masterPassword = PasswordBox.Password;

            if (string.IsNullOrEmpty(masterPassword))
            {
                MessageBox.Show("Master password cannot be empty.");
                return;
            }

            var allPasswords = PasswordManager.GetAllPasswords();

            if (allPasswords.Count > 0)
            {
                PasswordGrid.ItemsSource = allPasswords.Select(result => new PasswordEntry
                {
                    Title = result[0],
                    EncryptedPassword = result[1],
                    Url = result[2],
                    Comment = result[3],
                    DecryptedPassword = ""
                }).ToList();
            }
            else
            {
                MessageBox.Show("No passwords found.");
                PasswordGrid.ItemsSource = null;
            }
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameBox.Text;
            string password = PasswordBox.Password;

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Username and password cannot be empty.");
                return;
            }

            if (UserAuthentication.LoginUser(username, password))
            {
                MessageBox.Show("Login successful!");
                ManagePasswordsTab.IsEnabled = true;
                MainTabControl.SelectedItem = ManagePasswordsTab;
            }
            else
            {
                MessageBox.Show("Invalid username or password.");
            }
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameBox.Text;
            string password = PasswordBox.Password;

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Username and password cannot be empty.");
                return;
            }

            UserAuthentication.RegisterUser(username, password);
            MessageBox.Show("Registration successful!");
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            string title = SearchTitleBox.Text;
            string masterPassword = PasswordBox.Password;

            if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(masterPassword))
            {
                MessageBox.Show("Title and master password cannot be empty.");
                return;
            }

            var searchResults = PasswordManager.SearchPassword(title, masterPassword);

            if (searchResults.Count > 0)
            {
                PasswordGrid.ItemsSource = searchResults.Select(result => new PasswordEntry
                {
                    Title = result[0],
                    EncryptedPassword = result[1],
                    Url = result[2],
                    Comment = result[3],
                    DecryptedPassword = ""
                }).ToList();
            }
            else
            {
                MessageBox.Show("No password found with the given title.");
                PasswordGrid.ItemsSource = null;
            }

            //string title = SearchTitleBox.Text;
            //string masterPassword = PasswordBox.Password;

            //if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(masterPassword))
            //{
            //    MessageBox.Show("Title and master password cannot be empty.");
            //    return;
            //}

            //var searchResults = PasswordManager.SearchPassword(title, masterPassword);

            //if (searchResults.Count() > 0)
            //{
            //    PasswordGrid.ItemsSource = searchResults.Select(result => new PasswordEntry
            //    {
            //        Title = result[0],
            //        EncryptedPassword = result[1],
            //        Url = result[2],
            //        Comment = result[3],
            //        DecryptedPassword = ""
            //    }).ToList();
            //}
            //else
            //{
            //    MessageBox.Show("No password found with the given title.");
            //    PasswordGrid.ItemsSource = null;
            //}
        }

        private void AddPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var addPasswordWindow = new AddPasswordWindow();
            if (addPasswordWindow.ShowDialog() == true)
            {
                string title = addPasswordWindow.TitleBox.Text;
                string password = addPasswordWindow.PasswordBox.Password;
                string url = addPasswordWindow.UrlBox.Text;
                string comment = addPasswordWindow.CommentBox.Text;
                PasswordManager.SavePassword(title, password, url, comment, PasswordBox.Password);
                MessageBox.Show("Password added successfully.");
                RefreshDataGrid();
            }
        }

        private void UpdatePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string title = SearchTitleBox.Text;
            string newPassword = NewPasswordBox.Text; // Assuming you have a PasswordBox for entering the new password
            string masterPassword = PasswordBox.Password;

            if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(newPassword) || string.IsNullOrEmpty(masterPassword))
            {
                MessageBox.Show("Title, new password, and master password cannot be empty.");
                return;
            }

            PasswordManager.UpdatePassword(title, newPassword, masterPassword);
            MessageBox.Show("Password updated successfully.");
            RefreshDataGrid();
        }

        private void DeletePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string title = SearchTitleBox.Text;

            PasswordManager.DeletePassword(title);
            MessageBox.Show("Password deleted successfully.");
            RefreshDataGrid();
        }

        private void GenerateRandomPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            string randomPassword = PasswordManager.GenerateRandomPassword();
            Clipboard.SetText(randomPassword);
            MessageBox.Show("Random password generated and copied to clipboard.");
        }

        private void ShowPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            if (button == null)
            {
                MessageBox.Show("Button is null.");
                return;
            }

            var encryptedPassword = button.Tag as string;
            if (string.IsNullOrEmpty(encryptedPassword))
            {
                MessageBox.Show("Encrypted password is null or empty.");
                return;
            }

            string masterPassword = PasswordBox.Password;

            if (string.IsNullOrEmpty(masterPassword))
            {
                MessageBox.Show("Master password cannot be empty.");
                return;
            }

            try
            {
                var decryptedPassword = AesEncryption.DecryptString(encryptedPassword, masterPassword);

                var passwordEntry = button.DataContext as PasswordEntry;
                if (passwordEntry != null)
                {
                    passwordEntry.DecryptedPassword = decryptedPassword;
                    // Refresh the DataGrid to show the updated password
                    PasswordGrid.Items.Refresh();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to decrypt the password: {ex.Message}. Please make sure you entered the correct master password.");
            }
        }

        private void CopyPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            if (button == null)
            {
                MessageBox.Show("Button is null.");
                return;
            }

            var passwordEntry = button.DataContext as PasswordEntry;
            if (passwordEntry == null || string.IsNullOrEmpty(passwordEntry.DecryptedPassword))
            {
                MessageBox.Show("No decrypted password available to copy.");
                return;
            }

            Clipboard.SetText(passwordEntry.DecryptedPassword);
            MessageBox.Show("Password copied to clipboard.");
        }

        private void RefreshDataGrid()
        {
            // Assuming you want to refresh the grid with the latest search results
            string title = SearchTitleBox.Text;
            string masterPassword = PasswordBox.Password;

            if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(masterPassword))
            {
                MessageBox.Show("Title and master password cannot be empty.");
                return;
            }

            var searchResults = PasswordManager.SearchPassword(title, masterPassword);

            if (searchResults.Count > 0)
            {
                PasswordGrid.ItemsSource = searchResults.Select(result => new PasswordEntry
                {
                    Title = result[0],
                    EncryptedPassword = result[1],
                    Url = result[2],
                    Comment = result[3],
                    DecryptedPassword = ""
                }).ToList();
            }
            else
            {
                MessageBox.Show("No password found with the given title.");
                PasswordGrid.ItemsSource = null;
            }
        }
    }

    public class PasswordManager
    {
        private static readonly string PasswordFilePath = "passwords.csv";

        public static List<string[]> GetAllPasswords()
        {
            if (!File.Exists(PasswordFilePath)) return new List<string[]>();

            var lines = File.ReadAllLines(PasswordFilePath);
            var results = new List<string[]>();

            foreach (var line in lines)
            {
                var columns = line.Split(',');
                results.Add(columns);
            }

            return results;
        }

        public static void SavePassword(string title, string password, string url, string comment, string masterPassword)
        {
            var encryptedPassword = AesEncryption.EncryptString(password, masterPassword);
            var line = $"{title},{encryptedPassword},{url},{comment}";
            File.AppendAllLines(PasswordFilePath, new[] { line });
        }

        public static List<string[]> SearchPassword(string title, string masterPassword)
        {
            if (!File.Exists(PasswordFilePath)) return new List<string[]>();

            var lines = File.ReadAllLines(PasswordFilePath);
            var results = new List<string[]>();

            foreach (var line in lines)
            {
                var columns = line.Split(',');
                if (columns[0].Equals(title, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(columns);
                }
            }

            return results;
        }

        public static void UpdatePassword(string title, string newPassword, string masterPassword)
        {
            if (!File.Exists(PasswordFilePath)) return;

            var lines = File.ReadAllLines(PasswordFilePath);
            for (int i = 0; i < lines.Length; i++)
            {
                var columns = lines[i].Split(',');
                if (columns[0].Equals(title, StringComparison.OrdinalIgnoreCase))
                {
                    columns[1] = AesEncryption.EncryptString(newPassword, masterPassword);
                    lines[i] = string.Join(",", columns);
                    break;
                }
            }

            File.WriteAllLines(PasswordFilePath, lines);
        }

        public static void DeletePassword(string title)
        {
            if (!File.Exists(PasswordFilePath)) return;

            var lines = File.ReadAllLines(PasswordFilePath).ToList();
            lines.RemoveAll(line => line.Split(',')[0].Equals(title, StringComparison.OrdinalIgnoreCase));
            File.WriteAllLines(PasswordFilePath, lines);
        }

        public static string GenerateRandomPassword(int length = 12)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var res = new char[length];
            using var rng = new RNGCryptoServiceProvider();
            var uintBuffer = new byte[sizeof(uint)];

            for (int i = 0; i < length; i++)
            {
                rng.GetBytes(uintBuffer);
                var num = BitConverter.ToUInt32(uintBuffer, 0);
                res[i] = valid[(int)(num % (uint)valid.Length)];
            }

            return new string(res);
        }
    }
}
