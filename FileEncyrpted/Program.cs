using System.Security.Cryptography;
using System.Text;
using static FileEncyrpted.Program;

namespace FileEncyrpted
{
    internal class Program
    {
        public enum EncryptionDirection
        {
            Encrypt = 1,
            Decrypt = 2
        }

        public enum EncryptionType
        {
            BASE64 = 1,
            AES = 2,
        }

        static void Main(string[] args)
        {
            var direction = GetEncyrptionDirection();
            var encryptionType = GetEncryptionType();
            var filePath = GetFilePath();

            string password = string.Empty;
            if (encryptionType != EncryptionType.BASE64)
                password = GetPassword();

            HandleEncryption(direction, encryptionType, filePath, password);
        }

        private static EncryptionDirection GetEncyrptionDirection()
        {
            var list = Enum.GetValues(typeof(EncryptionDirection))
            .Cast<EncryptionDirection>()
            .Select(v => v.ToString())
            .ToList();

            list.ForEach(o => Console.WriteLine($"{(int)Enum.Parse(typeof(EncryptionDirection), o)}: {o}"));
            Console.Write("Enter encryption direction: ");
            var direction = Console.ReadLine();
            
            int _dirValue;
            while (!int.TryParse(direction, out _dirValue) || !Enum.IsDefined(typeof(EncryptionDirection), _dirValue))
            {
                Console.WriteLine("Invalid input.");
                Console.Write("Please enter a valid encryption direction: ");
                direction = Console.ReadLine();
            }

            return (EncryptionDirection)_dirValue;
        }

        private static string GetFilePath()
        {
            Console.Write("Enter file path: ");
            var filePath = Console.ReadLine();
            while (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
            {
                Console.WriteLine("Invalid file path.");
                Console.Write("Please enter a valid file path: ");
                filePath = Console.ReadLine();
            }
            return filePath;
        }

        private static string GetPassword()
        {
            Console.Write("Enter password: ");
            var password = Console.ReadLine();
            while (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Password cannot be empty.");
                Console.Write("Please enter a valid password: ");
                password = Console.ReadLine();
            }
            return password;
        }

        private static EncryptionType GetEncryptionType()
        {
            var list = Enum.GetValues(typeof(EncryptionType))
            .Cast<EncryptionType>()
            .Select(v => v.ToString())
            .ToList();
            list.ForEach(o => Console.WriteLine($"{(int)Enum.Parse(typeof(EncryptionType), o)}: {o}"));
            Console.Write("Enter encryption type: ");
            var encryptionType = Console.ReadLine();
            
            int _encryptionTypeValue;
            while (!int.TryParse(encryptionType, out _encryptionTypeValue) || !Enum.IsDefined(typeof(EncryptionType), _encryptionTypeValue))
            {
                Console.WriteLine("Invalid input.");
                Console.Write("Please enter a valid encryption type: ");
                encryptionType = Console.ReadLine();
            }

            return (EncryptionType)_encryptionTypeValue;
        }

        private static void AesEncryptFile(EncryptionType encryptionType, string filePath, string password)
        {
            var outputFile = GetOutputFilePath(EncryptionDirection.Encrypt, filePath, "txt");

            // Anahtar ve IV üret
            byte[] key = Encoding.UTF8.GetBytes(password);
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                byte[] iv = aes.IV;

                using (FileStream fsInput = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    // Önce IV'yi dosyaya yaz
                    fsEncrypted.Write(iv, 0, iv.Length);

                    using (CryptoStream cs = new CryptoStream(fsEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        fsInput.CopyTo(cs);
                    }
                }
            }
        }

        private static void AesDecryptFile(EncryptionType encryptionType, string filePath, string password)
        {
            var outputFile = GetOutputFilePath(EncryptionDirection.Decrypt, filePath, "txt");


            byte[] key = Encoding.UTF8.GetBytes(password);

            using (FileStream fsEncrypted = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] iv = new byte[16];
                fsEncrypted.Read(iv, 0, 16); // İlk 16 baytı IV olarak al

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (CryptoStream cs = new CryptoStream(fsEncrypted, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    {
                        cs.CopyTo(fsOutput);
                    }
                }
            }
        }

        private static void Base64EncryptFile(string filePath)
        {
            var outputFile = GetOutputFilePath(EncryptionDirection.Encrypt, filePath, "txt");

            var bytes = File.ReadAllBytes(filePath);
            var encryptedBytes = Convert.ToBase64String(bytes);

            File.WriteAllText(outputFile, encryptedBytes);
        }

        private static void Base64DecryptFile(string filePath)
        {
            var outputFile = GetOutputFilePath(EncryptionDirection.Decrypt, filePath, "txt");

            var base64Text = File.ReadAllText(filePath);
            var bytes = Convert.FromBase64String(base64Text);

            File.WriteAllBytes(outputFile, bytes);
        }

        private static void HandleEncryption(EncryptionDirection direction, EncryptionType encryptionType, string filePath, string password)
        {
            switch (direction)
            {
                case EncryptionDirection.Encrypt:
                    if (encryptionType == EncryptionType.BASE64)
                    {
                        Base64EncryptFile(filePath);
                    }
                    else if (encryptionType == EncryptionType.AES)
                    {
                        AesEncryptFile(encryptionType, filePath, password);
                    }
                    break;
                case EncryptionDirection.Decrypt:
                    if (encryptionType == EncryptionType.BASE64)
                    {
                        Base64DecryptFile(filePath);
                    }
                    else if (encryptionType == EncryptionType.AES)
                    {
                        AesDecryptFile(encryptionType, filePath, password);
                    }
                    break;
            }
        }

        private static string GetOutputFilePath(EncryptionDirection direction, string filePath, string extension)
        {
            var directory = Path.GetDirectoryName(filePath);
            var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(filePath);

            if (direction == EncryptionDirection.Encrypt)
            {
                return Path.Combine(directory, $"{fileNameWithoutExtension}_encrypted.{extension}");
            }
            else if (direction == EncryptionDirection.Decrypt)
            {
                fileNameWithoutExtension = fileNameWithoutExtension.Replace("_encrypted", string.Empty);
                return Path.Combine(directory, $"{fileNameWithoutExtension}.{extension}");
            }
            else
            {
                throw new ArgumentException("Invalid encryption direction.");
            }
        }
    }
}
