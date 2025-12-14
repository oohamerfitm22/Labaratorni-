using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoSuite
{
    public static class AsymmetricCrypto
    {
        private static string privateKeyPath = Path.Combine("keys", "priv.pem");
        private static string publicKeyPath = Path.Combine("keys", "pub.pem");

        private static RSA rsa;

        public static void GenerateKeys()
        {
            if (!Directory.Exists("keys")) Directory.CreateDirectory("keys");

            rsa = RSA.Create(2048);

            // Приватний ключ у PEM
            File.WriteAllText(privateKeyPath, ExportPrivateKeyToPem(rsa));

            // Публічний ключ у PEM
            File.WriteAllText(publicKeyPath, ExportPublicKeyToPem(rsa));
        }

        private static string ExportPrivateKeyToPem(RSA rsa)
        {
            var bytes = rsa.ExportPkcs8PrivateKey();
            return new string(PemEncoding.Write("PRIVATE KEY", bytes));
        }

        private static string ExportPublicKeyToPem(RSA rsa)
        {
            var bytes = rsa.ExportSubjectPublicKeyInfo();
            return new string(PemEncoding.Write("PUBLIC KEY", bytes));
        }

        public static byte[] EncryptRSA(byte[] data)
        {
            if (rsa == null) rsa = RSA.Create();
            return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        public static byte[] DecryptRSA(byte[] data)
        {
            if (rsa == null) rsa = RSA.Create();
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        // ==========================
        // Методи підпису
        // ==========================
        public static byte[] SignData(byte[] data)
        {
            if (rsa == null) rsa = RSA.Create();
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static bool VerifySignature(byte[] data, byte[] signature)
        {
            if (rsa == null) rsa = RSA.Create();
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
    }
}
