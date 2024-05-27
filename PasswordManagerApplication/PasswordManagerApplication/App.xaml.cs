using PasswordManagerApplication.AES;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace PasswordManagerApplication
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private static readonly string PasswordFilePath = "passwords.csv";
        private static readonly string EncryptedFilePath = "Encryptedpasswords.enc";
        private static readonly string MasterPassword = "1234"; // Set this to a secure value or prompt the user

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            DecryptPasswordFile();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
            EncryptPasswordFile();
        }

        private void DecryptPasswordFile()
        {
            if (File.Exists(EncryptedFilePath))
            {
                try
                {
                    var encryptedData = File.ReadAllBytes(EncryptedFilePath);
                    var decryptedData = AesEncryption.DecryptBytes(encryptedData, MasterPassword);
                    File.WriteAllBytes(PasswordFilePath, decryptedData);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to decrypt the password file: {ex.Message}");
                }
            }
        }

        private void EncryptPasswordFile()
        {
            if (File.Exists(PasswordFilePath))
            {
                try
                {
                    var data = File.ReadAllBytes(PasswordFilePath);
                    var encryptedData = AesEncryption.EncryptBytes(data, MasterPassword);
                    File.WriteAllBytes(EncryptedFilePath, encryptedData);
                    File.Delete(PasswordFilePath); // Remove the plain text file
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to encrypt the password file: {ex.Message}");
                }
            }
        }
    }

}
