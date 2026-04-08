using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Cyphera
{
    public class FF1
    {
        private readonly int _radix;
        private readonly byte[] _key;
        private readonly byte[] _tweak;
        private readonly string _alphabet;
        private readonly Dictionary<char, int> _charMap;

        public FF1(byte[] key, byte[] tweak, string alphabet = "0123456789abcdefghijklmnopqrstuvwxyz")
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Key must be 16, 24, or 32 bytes");
            if (alphabet.Length < 2)
                throw new ArgumentException("Alphabet must have >= 2 chars");

            _radix = alphabet.Length;
            _alphabet = alphabet;
            _key = (byte[])key.Clone();
            _tweak = (byte[])tweak.Clone();
            _charMap = new Dictionary<char, int>();
            for (int i = 0; i < alphabet.Length; i++) _charMap[alphabet[i]] = i;
        }

        public string Encrypt(string plaintext) => FromDigits(FF1Encrypt(ToDigits(plaintext), _tweak));
        public string Decrypt(string ciphertext) => FromDigits(FF1Decrypt(ToDigits(ciphertext), _tweak));

        private int[] ToDigits(string s) => s.Select(c => _charMap[c]).ToArray();
        private string FromDigits(int[] d) => new string(d.Select(i => _alphabet[i]).ToArray());

        private int[] FF1Encrypt(int[] pt, byte[] T)
        {
            int n = pt.Length, u = n / 2, v = n - u;
            int[] A = pt[..u], B = pt[u..];
            int b = ComputeB(v);
            int d = 4 * ((b + 3) / 4) + 4;
            byte[] P = BuildP(u, n, T.Length);

            for (int i = 0; i < 10; i++)
            {
                var numB = BigIntToBytes(Num(B), b);
                var Q = BuildQ(T, i, numB, b);
                var R = PRF(Concat(P, Q));
                var S = ExpandS(R, d);
                var y = new BigInteger(S, isUnsigned: true, isBigEndian: true);
                int m = i % 2 == 0 ? u : v;
                var c = (Num(A) + y) % BigInteger.Pow(_radix, m);
                A = B; B = Str(c, m);
            }
            return A.Concat(B).ToArray();
        }

        private int[] FF1Decrypt(int[] ct, byte[] T)
        {
            int n = ct.Length, u = n / 2, v = n - u;
            int[] A = ct[..u], B = ct[u..];
            int b = ComputeB(v);
            int d = 4 * ((b + 3) / 4) + 4;
            byte[] P = BuildP(u, n, T.Length);

            for (int i = 9; i >= 0; i--)
            {
                var numA = BigIntToBytes(Num(A), b);
                var Q = BuildQ(T, i, numA, b);
                var R = PRF(Concat(P, Q));
                var S = ExpandS(R, d);
                var y = new BigInteger(S, isUnsigned: true, isBigEndian: true);
                int m = i % 2 == 0 ? u : v;
                var mod = BigInteger.Pow(_radix, m);
                var c = ((Num(B) - y) % mod + mod) % mod;
                B = A; A = Str(c, m);
            }
            return A.Concat(B).ToArray();
        }

        private int ComputeB(int v)
        {
            var pow = BigInteger.Pow(_radix, v) - 1;
            int bits = pow.IsZero ? 1 : (int)pow.GetBitLength();
            return (bits + 7) / 8;
        }

        private byte[] BuildP(int u, int n, int t)
        {
            byte[] P = new byte[16];
            P[0] = 1; P[1] = 2; P[2] = 1;
            P[3] = (byte)(_radix >> 16); P[4] = (byte)(_radix >> 8); P[5] = (byte)_radix;
            P[6] = 10; P[7] = (byte)u;
            P[8] = (byte)(n >> 24); P[9] = (byte)(n >> 16); P[10] = (byte)(n >> 8); P[11] = (byte)n;
            P[12] = (byte)(t >> 24); P[13] = (byte)(t >> 16); P[14] = (byte)(t >> 8); P[15] = (byte)t;
            return P;
        }

        private byte[] BuildQ(byte[] T, int i, byte[] numBytes, int b)
        {
            int pad = (16 - ((T.Length + 1 + b) % 16)) % 16;
            var Q = new byte[T.Length + pad + 1 + b];
            Array.Copy(T, 0, Q, 0, T.Length);
            Q[T.Length + pad] = (byte)i;
            int srcStart = Math.Max(0, numBytes.Length - b);
            int destStart = Q.Length - (numBytes.Length - srcStart);
            Array.Copy(numBytes, srcStart, Q, destStart, numBytes.Length - srcStart);
            return Q;
        }

        private byte[] PRF(byte[] data)
        {
            byte[] y = new byte[16];
            for (int off = 0; off < data.Length; off += 16)
            {
                byte[] tmp = new byte[16];
                for (int j = 0; j < 16; j++) tmp[j] = (byte)(y[j] ^ data[off + j]);
                y = AesEcb(tmp);
            }
            return y;
        }

        private byte[] ExpandS(byte[] R, int d)
        {
            int blocks = (d + 15) / 16;
            byte[] outBuf = new byte[blocks * 16];
            Array.Copy(R, 0, outBuf, 0, 16);
            for (int j = 1; j < blocks; j++)
            {
                byte[] x = new byte[16];
                x[12] = (byte)(j >> 24); x[13] = (byte)(j >> 16); x[14] = (byte)(j >> 8); x[15] = (byte)j;
                for (int k = 0; k < 16; k++) x[k] ^= R[k];
                var enc = AesEcb(x);
                Array.Copy(enc, 0, outBuf, j * 16, 16);
            }
            return outBuf[..d];
        }

        private byte[] AesEcb(byte[] block)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            return aes.EncryptEcb(block, PaddingMode.None);
        }

        private byte[] BigIntToBytes(BigInteger x, int b)
        {
            var bytes = x.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length >= b) return bytes[^b..];
            var result = new byte[b];
            Array.Copy(bytes, 0, result, b - bytes.Length, bytes.Length);
            return result;
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

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Array.Copy(a, 0, r, 0, a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            return r;
        }

        public static FF1 Digits(byte[] key, byte[] tweak) => new FF1(key, tweak, "0123456789");
        public static FF1 Alphanumeric(byte[] key, byte[] tweak) => new FF1(key, tweak);
        public static byte[] HexToBytes(string hex)
        {
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                r[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return r;
        }
    }
}
