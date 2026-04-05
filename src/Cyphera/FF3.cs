using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Cyphera
{
    public class FF3
    {
        private readonly int _radix;
        private readonly byte[] _key;
        private readonly byte[] _tweak;
        private readonly string _alphabet;
        private readonly Dictionary<char, int> _charMap;

        public FF3(byte[] key, byte[] tweak, string alphabet = "0123456789abcdefghijklmnopqrstuvwxyz")
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Key must be 16, 24, or 32 bytes");
            if (tweak.Length != 8)
                throw new ArgumentException("Tweak must be exactly 8 bytes");
            if (alphabet.Length < 2)
                throw new ArgumentException("Alphabet must have >= 2 chars");

            _radix = alphabet.Length;
            _alphabet = alphabet;
            _tweak = (byte[])tweak.Clone();
            _key = key.Reverse().ToArray();
            _charMap = new Dictionary<char, int>();
            for (int i = 0; i < alphabet.Length; i++) _charMap[alphabet[i]] = i;
        }

        public string Encrypt(string plaintext) => FromDigits(FF3Encrypt(ToDigits(plaintext)));
        public string Decrypt(string ciphertext) => FromDigits(FF3Decrypt(ToDigits(ciphertext)));

        private int[] ToDigits(string s) => s.Select(c => _charMap[c]).ToArray();
        private string FromDigits(int[] d) => new string(d.Select(i => _alphabet[i]).ToArray());

        private int[] FF3Encrypt(int[] pt)
        {
            int n = pt.Length, u = (n + 1) / 2, v = n - u;
            int[] A = pt[..u], B = pt[u..];

            for (int i = 0; i < 8; i++)
            {
                byte[] w = i % 2 == 0 ? _tweak[4..8] : _tweak[0..4];
                if (i % 2 == 0)
                {
                    var p = CalcP(i, w, B);
                    var m = BigInteger.Pow(_radix, u);
                    var aNum = Num(Reverse(A));
                    var y = (aNum + p) % m;
                    A = Reverse(Str(y, u));
                }
                else
                {
                    var p = CalcP(i, w, A);
                    var m = BigInteger.Pow(_radix, v);
                    var bNum = Num(Reverse(B));
                    var y = (bNum + p) % m;
                    B = Reverse(Str(y, v));
                }
            }
            return A.Concat(B).ToArray();
        }

        private int[] FF3Decrypt(int[] ct)
        {
            int n = ct.Length, u = (n + 1) / 2, v = n - u;
            int[] A = ct[..u], B = ct[u..];

            for (int i = 7; i >= 0; i--)
            {
                byte[] w = i % 2 == 0 ? _tweak[4..8] : _tweak[0..4];
                if (i % 2 == 0)
                {
                    var p = CalcP(i, w, B);
                    var m = BigInteger.Pow(_radix, u);
                    var aNum = Num(Reverse(A));
                    var y = ((aNum - p) % m + m) % m;
                    A = Reverse(Str(y, u));
                }
                else
                {
                    var p = CalcP(i, w, A);
                    var m = BigInteger.Pow(_radix, v);
                    var bNum = Num(Reverse(B));
                    var y = ((bNum - p) % m + m) % m;
                    B = Reverse(Str(y, v));
                }
            }
            return A.Concat(B).ToArray();
        }

        private BigInteger CalcP(int round, byte[] w, int[] half)
        {
            byte[] input = new byte[16];
            Array.Copy(w, 0, input, 0, 4);
            input[3] ^= (byte)round;

            var revHalf = Reverse(half);
            var halfNum = Num(revHalf);
            var hb = halfNum.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (hb.Length <= 12) Array.Copy(hb, 0, input, 16 - hb.Length, hb.Length);
            else Array.Copy(hb, hb.Length - 12, input, 4, 12);

            var revInput = input.Reverse().ToArray();
            var aesOut = AesEcb(revInput);
            var revOut = aesOut.Reverse().ToArray();
            return new BigInteger(revOut, isUnsigned: true, isBigEndian: true);
        }

        private byte[] AesEcb(byte[] block)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            return aes.EncryptEcb(block, PaddingMode.None);
        }

        private BigInteger Num(int[] digits)
        {
            BigInteger r = 0;
            foreach (var d in digits) r = r * _radix + d;
            return r;
        }

        private int[] Str(BigInteger num, int len)
        {
            int[] r = new int[len];
            for (int i = len - 1; i >= 0; i--) { r[i] = (int)(num % _radix); num /= _radix; }
            return r;
        }

        private static int[] Reverse(int[] a) => a.Reverse().ToArray();

        public static FF3 Digits(byte[] key, byte[] tweak) => new FF3(key, tweak, "0123456789");
        public static byte[] HexToBytes(string hex)
        {
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                r[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return r;
        }
    }
}
