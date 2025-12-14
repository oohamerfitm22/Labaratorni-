using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoSuite
{
    public static class HybridCrypto
    {
        public static byte[] EncryptHybrid(byte[] data)
        {
            // Згенеруємо випадковий AES ключ
            byte[] aesKey = RandomNumberGenerator.GetBytes(32);
            byte[] encData = SymmetricCrypto.EncryptAES(data); // AES шифрування

            // RSA публічний ключ
            AsymmetricCrypto.GenerateKeys();
            byte[] encKey = AsymmetricCrypto.EncryptRSA(aesKey);

            // Пакуємо: [довжина ключа(4байт)] + encKey + encData
            byte[] result = new byte[4 + encKey.Length + encData.Length];
            byte[] lenBytes = BitConverter.GetBytes(encKey.Length);
            Buffer.BlockCopy(lenBytes, 0, result, 0, 4);
            Buffer.BlockCopy(encKey, 0, result, 4, encKey.Length);
            Buffer.BlockCopy(encData, 0, result, 4 + encKey.Length, encData.Length);
            return result;
        }

        public static byte[] DecryptHybrid(byte[] data)
        {
            int len = BitConverter.ToInt32(data, 0);
            byte[] encKey = new byte[len];
            byte[] encData = new byte[data.Length - 4 - len];
            Buffer.BlockCopy(data, 4, encKey, 0, len);
            Buffer.BlockCopy(data, 4 + len, encData, 0, encData.Length);

            byte[] aesKey = AsymmetricCrypto.DecryptRSA(encKey);
            // Для простоти використовуємо SymmetricCrypto з внутрішнім ключем
            return SymmetricCrypto.DecryptAES(encData);
        }
    }
}
