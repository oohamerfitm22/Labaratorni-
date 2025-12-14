using System;
using System.IO;
using System.Diagnostics;
using System.Text;

namespace CryptoSuite
{
    public static class Benchmark
    {
        public static void RunAll()
        {
            string testFile = Path.Combine("data", "benchmark_sample.txt");
            if (!File.Exists(testFile))
            {
                File.WriteAllText(testFile, "Це тестовий файл для бенчмаркування.\nПовторимо рядок кілька разів.\n" + new string('A', 1024 * 10));
            }

            byte[] data = File.ReadAllBytes(testFile);

            Console.WriteLine("=== Benchmark AES-GCM ===");
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] enc = SymmetricCrypto.EncryptAES(data);
            sw.Stop();
            Console.WriteLine($"AES Encrypt: {sw.ElapsedMilliseconds} ms, розмір: {enc.Length} байт");

            sw.Restart();
            byte[] dec = SymmetricCrypto.DecryptAES(enc);
            sw.Stop();
            Console.WriteLine($"AES Decrypt: {sw.ElapsedMilliseconds} ms");

            Console.WriteLine("\n=== Benchmark RSA ===");
            AsymmetricCrypto.GenerateKeys();
            sw.Restart();
            byte[] encRsa = AsymmetricCrypto.EncryptRSA(data.Length > 190 ? new byte[190] : data); // RSA обмежений розмір
            sw.Stop();
            Console.WriteLine($"RSA Encrypt: {sw.ElapsedMilliseconds} ms, розмір: {encRsa.Length} байт");

            sw.Restart();
            byte[] decRsa = AsymmetricCrypto.DecryptRSA(encRsa);
            sw.Stop();
            Console.WriteLine($"RSA Decrypt: {sw.ElapsedMilliseconds} ms");

            // Запис результатів у CSV
            string csvPath = Path.Combine("outputs", "benchmark_results.csv");
            using (var writer = new StreamWriter(csvPath, false, Encoding.UTF8))
            {
                writer.WriteLine("Algorithm,Operation,Time_ms,OutputSize_bytes");
                writer.WriteLine($"AES-GCM,Encrypt,{sw.ElapsedMilliseconds},{enc.Length}");
                writer.WriteLine($"AES-GCM,Decrypt,{sw.ElapsedMilliseconds},{dec.Length}");
                writer.WriteLine($"RSA,Encrypt,{sw.ElapsedMilliseconds},{encRsa.Length}");
                writer.WriteLine($"RSA,Decrypt,{sw.ElapsedMilliseconds},{decRsa.Length}");
            }

            Console.WriteLine($"\nBenchmark завершено. Результати збережено у {csvPath}");
        }
    }
}
