using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PasswordManagerApplication.AES
{
    public class AesEncryption
    {
        private static readonly byte[] Salt = Encoding.ASCII.GetBytes("qwertyuiopasdfghjklzxcvbnm[]1234567890-=/.,`-*|}{?><:");

        public static string EncryptString(string plainText, string password)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (password == null) throw new ArgumentNullException(nameof(password));

            using var aes = Aes.Create();
            var key = new Rfc2898DeriveBytes(password, Salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.GenerateIV(); // Generate a new IV for each encryption

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }

            var encryptedContent = ms.ToArray();
            var result = new byte[aes.IV.Length + encryptedContent.Length];

            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedContent, 0, result, aes.IV.Length, encryptedContent.Length);

            return Convert.ToBase64String(result);
        }

        public static string DecryptString(string cipherText, string password)
        {
            if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var fullCipher = Convert.FromBase64String(cipherText);

            using var aes = Aes.Create();
            var key = new Rfc2898DeriveBytes(password, Salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);

            var iv = new byte[aes.BlockSize / 8];
            var cipherBytes = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);

            aes.IV = iv;

            using var ms = new MemoryStream(cipherBytes);
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);

            return sr.ReadToEnd();
        }

        public static byte[] EncryptBytes(byte[] plainBytes, string password)
        {
            if (plainBytes == null) throw new ArgumentNullException(nameof(plainBytes));
            if (password == null) throw new ArgumentNullException(nameof(password));

            using var aes = Aes.Create();
            var key = new Rfc2898DeriveBytes(password, Salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.GenerateIV();

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
            ms.Write(aes.IV, 0, aes.IV.Length); // Write IV to the beginning of the stream
            cs.Write(plainBytes, 0, plainBytes.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        public static byte[] DecryptBytes(byte[] cipherBytes, string password)
        {
            if (cipherBytes == null) throw new ArgumentNullException(nameof(cipherBytes));
            if (password == null) throw new ArgumentNullException(nameof(password));

            using var aes = Aes.Create();
            var key = new Rfc2898DeriveBytes(password, Salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);

            using var ms = new MemoryStream(cipherBytes);
            var iv = new byte[aes.BlockSize / 8];
            ms.Read(iv, 0, iv.Length); // Read IV from the beginning of the stream
            aes.IV = iv;

            using var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read);
            using var output = new MemoryStream();
            cs.CopyTo(output);

            return output.ToArray();
        }
    }

    //public class AesEncryption
    //{
    //    private static readonly byte[] Salt = Encoding.ASCII.GetBytes("qwertyuiopasdfghjklzxcvbnm[]1234567890-=/.,`-*|}{?><:");

    //    public static string EncryptString(string plainText, string password)
    //    {
    //        if (plainText == null) throw new ArgumentNullException(nameof(plainText));
    //        if (password == null) throw new ArgumentNullException(nameof(password));

    //        using var aes = Aes.Create();
    //        var key = new Rfc2898DeriveBytes(password, Salt, 10000);
    //        aes.Key = key.GetBytes(aes.KeySize / 8);
    //        aes.GenerateIV(); // Generate a new IV for each encryption

    //        using var ms = new MemoryStream();
    //        using var cs = new CryptoStream(ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
    //        using (var sw = new StreamWriter(cs))
    //        {
    //            sw.Write(plainText);
    //        }

    //        var encryptedContent = ms.ToArray();
    //        var result = new byte[aes.IV.Length + encryptedContent.Length];

    //        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
    //        Buffer.BlockCopy(encryptedContent, 0, result, aes.IV.Length, encryptedContent.Length);

    //        return Convert.ToBase64String(result);
    //    }

    //    public static string DecryptString(string cipherText, string password)
    //    {
    //        if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
    //        if (password == null) throw new ArgumentNullException(nameof(password));

    //        var fullCipher = Convert.FromBase64String(cipherText);

    //        using var aes = Aes.Create();
    //        var key = new Rfc2898DeriveBytes(password, Salt, 10000);
    //        aes.Key = key.GetBytes(aes.KeySize / 8);

    //        var iv = new byte[aes.BlockSize / 8];
    //        var cipherBytes = new byte[fullCipher.Length - iv.Length];

    //        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
    //        Buffer.BlockCopy(fullCipher, iv.Length, cipherBytes, 0, cipherBytes.Length);

    //        aes.IV = iv;

    //        using var ms = new MemoryStream(cipherBytes);
    //        using var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read);
    //        using var sr = new StreamReader(cs);

    //        return sr.ReadToEnd();
    //    }
    //}
}
