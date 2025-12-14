using System;
using System.Security.Cryptography;

namespace CryptoSuite
{
    public static class SymmetricCrypto
    {
        private static byte[] key = RandomNumberGenerator.GetBytes(32); // AES-256
        private static byte[] nonce = RandomNumberGenerator.GetBytes(12); // GCM

        public static byte[] EncryptAES(byte[] plaintext)
        {
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using (AesGcm aes = new AesGcm(key))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);

            return result;
        }

        public static byte[] DecryptAES(byte[] input)
        {
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[input.Length - 28];

            Buffer.BlockCopy(input, 0, nonce, 0, 12);
            Buffer.BlockCopy(input, 12, tag, 0, 16);
            Buffer.BlockCopy(input, 28, ciphertext, 0, ciphertext.Length);

            byte[] plaintext = new byte[ciphertext.Length];

            using (AesGcm aes = new AesGcm(key))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }
    }
}
