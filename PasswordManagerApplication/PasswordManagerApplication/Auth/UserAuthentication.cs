using System.IO;
using System.Security.Cryptography;

namespace PasswordManagerApplication.Auth
{
    public class UserAuthentication
    {
        private static readonly string UserFilePath = "user_credentials.txt";

        public static void RegisterUser(string username, string password)
        {
            var hashedPassword = HashPassword(password);
            File.WriteAllText(UserFilePath, $"{username}:{hashedPassword}");
        }

        public static bool LoginUser(string username, string password)
        {
            if (!File.Exists(UserFilePath)) return false;

            var storedCredentials = File.ReadAllText(UserFilePath).Split(':');
            if (storedCredentials[0] != username) return false;

            return VerifyPassword(password, storedCredentials[1]);
        }

        private static string HashPassword(string password)
        {
            using var rfc2898 = new Rfc2898DeriveBytes(password, 16, 10000);
            var salt = rfc2898.Salt;
            var hash = rfc2898.GetBytes(20);
            var hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            var hashBytes = Convert.FromBase64String(storedHash);
            var salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);

            using var rfc2898 = new Rfc2898DeriveBytes(password, salt, 10000);
            var hash = rfc2898.GetBytes(20);

            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 16] != hash[i])
                    return false;

            return true;
        }
    }
}
