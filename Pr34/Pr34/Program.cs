using System;
using System.IO;
using CryptoSuite;

namespace CryptoSuiteApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Створюємо всі потрібні папки
            CreateFolderIfNotExist("data");
            CreateFolderIfNotExist("outputs");
            CreateFolderIfNotExist("keys");
            CreateFolderIfNotExist("logs");

            while (true)
            {
                Console.WriteLine("\nВиберіть операцію:");
                Console.WriteLine("1 - AES (симетричне шифрування)");
                Console.WriteLine("2 - RSA (асиметричне шифрування)");
                Console.WriteLine("3 - Hybrid (гібридне шифрування)");
                Console.WriteLine("4 - Benchmark");
                Console.WriteLine("0 - Вихід");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        DoAES();
                        break;
                    case "2":
                        DoRSA();
                        break;
                    case "3":
                        DoHybrid();
                        break;
                    case "4":
                        Benchmark.RunAll();
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Невірний вибір.");
                        break;
                }
            }
        }

        static void CreateFolderIfNotExist(string folderName)
        {
            if (!Directory.Exists(folderName))
            {
                Directory.CreateDirectory(folderName);
            }
        }

        static string GetFilePathFromUser()
        {
            Console.Write("Введіть назву файлу (з розширенням) з папки data/: ");
            string filename = Console.ReadLine();

            string projectPath = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.FullName;
            string inputPath = Path.Combine(projectPath, "data", filename);

            if (!File.Exists(inputPath))
            {
                Console.WriteLine($"Файл {filename} не знайдено у папці data!");
                return null;
            }

            return inputPath;
        }

        static void DoAES()
        {
            string inputPath = GetFilePathFromUser();
            if (inputPath == null) return;

            byte[] data = File.ReadAllBytes(inputPath);

            byte[] enc = SymmetricCrypto.EncryptAES(data);
            string encPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_enc.bin");
            File.WriteAllBytes(encPath, enc);
            Console.WriteLine($"Файл зашифровано: {encPath}");

            byte[] dec = SymmetricCrypto.DecryptAES(enc);
            string decPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_dec.txt");
            File.WriteAllBytes(decPath, dec);
            Console.WriteLine($"Файл розшифровано: {decPath}");
        }

        static void DoRSA()
        {
            string inputPath = GetFilePathFromUser();
            if (inputPath == null) return;

            byte[] data = File.ReadAllBytes(inputPath);

            AsymmetricCrypto.GenerateKeys();

            byte[] enc = AsymmetricCrypto.EncryptRSA(data.Length > 190 ? new byte[190] : data);
            string encPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_enc_rsa.bin");
            File.WriteAllBytes(encPath, enc);
            Console.WriteLine($"Файл зашифровано RSA: {encPath}");

            byte[] dec = AsymmetricCrypto.DecryptRSA(enc);
            string decPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_dec_rsa.txt");
            File.WriteAllBytes(decPath, dec);
            Console.WriteLine($"Файл розшифровано RSA: {decPath}");

            byte[] signature = AsymmetricCrypto.SignData(data);
            string sigPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + ".sig");
            File.WriteAllBytes(sigPath, signature);

            bool verified = AsymmetricCrypto.VerifySignature(data, signature);
            Console.WriteLine($"Підпис валідний: {verified}");
        }

        static void DoHybrid()
        {
            string inputPath = GetFilePathFromUser();
            if (inputPath == null) return;

            byte[] data = File.ReadAllBytes(inputPath);

            AsymmetricCrypto.GenerateKeys();

            byte[] hybridEnc = HybridCrypto.EncryptHybrid(data);
            string encPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_hybrid.bin");
            File.WriteAllBytes(encPath, hybridEnc);
            Console.WriteLine($"Файл зашифровано гібридно: {encPath}");

            byte[] hybridDec = HybridCrypto.DecryptHybrid(hybridEnc);
            string decPath = Path.Combine("outputs", Path.GetFileNameWithoutExtension(inputPath) + "_hybrid_dec.txt");
            File.WriteAllBytes(decPath, hybridDec);
            Console.WriteLine($"Файл розшифровано гібридно: {decPath}");
        }
    }
}
