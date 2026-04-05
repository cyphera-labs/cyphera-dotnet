using Xunit;
using Cyphera;

namespace Cyphera.Tests
{
    public class FF1NISTTests
    {
        static byte[] Hex(string h) => FF1.HexToBytes(h);

        [Fact] public void Sample1() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3C"), Array.Empty<byte>()); Assert.Equal("2433477484", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("2433477484")); }
        [Fact] public void Sample2() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3C"), Hex("39383736353433323130")); Assert.Equal("6124200773", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("6124200773")); }
        [Fact] public void Sample3() { var c = FF1.Alphanumeric(Hex("2B7E151628AED2A6ABF7158809CF4F3C"), Hex("3737373770717273373737")); Assert.Equal("a9tv40mll9kdu509eum", c.Encrypt("0123456789abcdefghi")); Assert.Equal("0123456789abcdefghi", c.Decrypt("a9tv40mll9kdu509eum")); }
        [Fact] public void Sample4() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), Array.Empty<byte>()); Assert.Equal("2830668132", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("2830668132")); }
        [Fact] public void Sample5() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), Hex("39383736353433323130")); Assert.Equal("2496655549", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("2496655549")); }
        [Fact] public void Sample6() { var c = FF1.Alphanumeric(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), Hex("3737373770717273373737")); Assert.Equal("xbj3kv35jrawxv32ysr", c.Encrypt("0123456789abcdefghi")); Assert.Equal("0123456789abcdefghi", c.Decrypt("xbj3kv35jrawxv32ysr")); }
        [Fact] public void Sample7() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), Array.Empty<byte>()); Assert.Equal("6657667009", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("6657667009")); }
        [Fact] public void Sample8() { var c = FF1.Digits(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), Hex("39383736353433323130")); Assert.Equal("1001623463", c.Encrypt("0123456789")); Assert.Equal("0123456789", c.Decrypt("1001623463")); }
        [Fact] public void Sample9() { var c = FF1.Alphanumeric(Hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), Hex("3737373770717273373737")); Assert.Equal("xs8a0azh2avyalyzuwd", c.Encrypt("0123456789abcdefghi")); Assert.Equal("0123456789abcdefghi", c.Decrypt("xs8a0azh2avyalyzuwd")); }
    }
}
