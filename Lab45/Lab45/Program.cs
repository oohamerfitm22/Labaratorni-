using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class CryptoModule
{
    public byte[] Key { get; private set; }
    public byte[] Salt { get; private set; }

    public CryptoModule(string password)
    {
        Salt = GenerateRandomBytes(32); // випадковий salt
        var keyDerive = new Rfc2898DeriveBytes(password, Salt, 100000, HashAlgorithmName.SHA256);
        Key = keyDerive.GetBytes(32); // AES-256
    }

    public static byte[] GenerateRandomBytes(int length)
    {
        var data = new byte[length];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    // AES-CBC
    public byte[] EncryptCBC(byte[] input, out byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = Key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        iv = GenerateRandomBytes(16);
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(input, 0, input.Length);
    }

    public byte[] DecryptCBC(byte[] input, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = Key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(input, 0, input.Length);
    }

    // AES-GCM
    public byte[] EncryptGCM(byte[] input, out byte[] nonce, out byte[] tag)
    {
        nonce = GenerateRandomBytes(12);
        tag = new byte[16];

        byte[] cipher = new byte[input.Length];

        using var gcm = new AesGcm(Key);
        gcm.Encrypt(nonce, input, cipher, tag);

        return cipher;
    }

    public byte[] DecryptGCM(byte[] cipher, byte[] nonce, byte[] tag)
    {
        byte[] output = new byte[cipher.Length];

        using var gcm = new AesGcm(Key);

        try
        {
            gcm.Decrypt(nonce, cipher, tag, output);
        }
        catch
        {
            Console.WriteLine("❌ ПОМИЛКА: Тег автентифiкації некоректний! Данi були підмінені.");
            return null;
        }

        return output;
    }
}

class Logger
{
    private static string LogFile = "crypto_log.txt";

    public static void Log(string message)
    {
        File.AppendAllText(LogFile, DateTime.Now + " | " + message + "\n");
    }
}

class Program
{
    static void Main()
    {
        Console.WriteLine("Введiть пароль для генерацiї ключа:");
        string password = Console.ReadLine();

        var crypto = new CryptoModule(password);

        while (true)
        {
            Console.WriteLine("\n=== МЕНЮ ===");
            Console.WriteLine("1 — Зашифрувати файл (CBC)");
            Console.WriteLine("2 — Розшифрувати файл (CBC)");
            Console.WriteLine("3 — Зашифрувати файл (GCM)");
            Console.WriteLine("4 — Розшифрувати файл (GCM)");
            Console.WriteLine("5 — iмітувати пiдмiну файлу (GCM)");
            Console.WriteLine("0 — Вихiд");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1": EncryptCBC(crypto); break;
                case "2": DecryptCBC(crypto); break;
                case "3": EncryptGCM(crypto); break;
                case "4": DecryptGCM(crypto); break;
                case "5": TamperSimulation(crypto); break;
                case "0": return;
            }
        }
    }

    static void EncryptCBC(CryptoModule crypto)
    {
        Console.WriteLine("Файл для шифрування:");
        string path = Console.ReadLine();

        byte[] data = File.ReadAllBytes(path);

        var cipher = crypto.EncryptCBC(data, out var iv);

        File.WriteAllBytes("encrypted_cbc.bin", cipher);
        File.WriteAllBytes("cbc_iv.bin", iv);

        Logger.Log("Успiшне шифрування CBC");
        Console.WriteLine("Готово");
    }

    static void DecryptCBC(CryptoModule crypto)
    {
        try
        {
            byte[] cipher = File.ReadAllBytes("encrypted_cbc.bin");
            byte[] iv = File.ReadAllBytes("cbc_iv.bin");

            byte[] plain = crypto.DecryptCBC(cipher, iv);
            File.WriteAllBytes("decrypted_cbc.txt", plain);

            Logger.Log("Успiшне дешифрування CBC");
            Console.WriteLine("Готово");
        }
        catch
        {
            Logger.Log("Помилка дешифрування CBC");
            Console.WriteLine("Помилка");
        }
    }

    static void EncryptGCM(CryptoModule crypto)
    {
        Console.WriteLine("Файл для шифрування:");
        string path = Console.ReadLine();

        byte[] data = File.ReadAllBytes(path);

        var cipher = crypto.EncryptGCM(data, out var nonce, out var tag);

        File.WriteAllBytes("encrypted_gcm.bin", cipher);
        File.WriteAllBytes("gcm_nonce.bin", nonce);
        File.WriteAllBytes("gcm_tag.bin", tag);

        Logger.Log("Усп]шне шифрування GCM");
        Console.WriteLine("Готово");
    }

    static void DecryptGCM(CryptoModule crypto)
    {
        try
        {
            byte[] cipher = File.ReadAllBytes("encrypted_gcm.bin");
            byte[] nonce = File.ReadAllBytes("gcm_nonce.bin");
            byte[] tag = File.ReadAllBytes("gcm_tag.bin");

            var plain = crypto.DecryptGCM(cipher, nonce, tag);

            if (plain != null)
            {
                File.WriteAllBytes("decrypted_gcm.txt", plain);
                Logger.Log("Успiшне дешифрування GCM");
                Console.WriteLine("Готово");
            }
        }
        catch
        {
            Logger.Log("ПОМИЛКА дешифрування GCM");
        }
    }

    static void TamperSimulation(CryptoModule crypto)
    {
        Console.WriteLine("Пiдмiняю тег…");

        byte[] badTag = CryptoModule.GenerateRandomBytes(16);
        File.WriteAllBytes("gcm_tag.bin", badTag);

        Console.WriteLine("Тепер спробуй дешифрувати у пункті 4.");
        Logger.Log("Iмітація атаки: тег пiдмiнено");
    }
}
