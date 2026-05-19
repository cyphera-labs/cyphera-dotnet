using System.Text.Json;
using Xunit;

namespace Cyphera.Tests
{
    public class CypheraTests
    {
        private static readonly string ConfigJson = @"{
            ""configurations"": {
                ""ssn"": { ""engine"": ""ff1"", ""key_ref"": ""test-key"", ""header"": ""T01"" },
                ""ssn_digits"": { ""engine"": ""ff1"", ""alphabet"": ""digits"", ""header_enabled"": false, ""key_ref"": ""test-key"" },
                ""ssn_mask"": { ""engine"": ""mask"", ""pattern"": ""last4"", ""header_enabled"": false },
                ""ssn_hash"": { ""engine"": ""hash"", ""algorithm"": ""sha256"", ""key_ref"": ""test-key"", ""header_enabled"": false }
            },
            ""keys"": {
                ""test-key"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" }
            }
        }";

        private static Cyphera CreateClient()
        {
            var doc = JsonDocument.Parse(ConfigJson);
            return Cyphera.FromConfig(doc.RootElement);
        }

        [Fact]
        public void ProtectAccessWithHeader()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123456789", "ssn");
            Assert.StartsWith("T01", protected_);
            Assert.True(protected_.Length > "123456789".Length);
            var accessed = c.AccessByHeader(protected_);
            Assert.Equal("123456789", accessed);
        }

        [Fact]
        public void ProtectAccessWithPassthroughs()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123-45-6789", "ssn");
            Assert.Contains("-", protected_);
            var accessed = c.AccessByHeader(protected_);
            Assert.Equal("123-45-6789", accessed);
        }

        [Fact]
        public void UnheaderedDigitsRoundtrip()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123456789", "ssn_digits");
            Assert.Equal(9, protected_.Length);
            var accessed = c.Access(protected_, "ssn_digits");
            Assert.Equal("123456789", accessed);
        }

        [Fact]
        public void Deterministic()
        {
            var c = CreateClient();
            var a = c.Protect("123456789", "ssn");
            var b = c.Protect("123456789", "ssn");
            Assert.Equal(a, b);
        }

        [Fact]
        public void MaskLast4()
        {
            var c = CreateClient();
            var result = c.Protect("123-45-6789", "ssn_mask");
            Assert.Equal("*******6789", result);
        }

        [Fact]
        public void HashDeterministic()
        {
            var c = CreateClient();
            var a = c.Protect("123-45-6789", "ssn_hash");
            var b = c.Protect("123-45-6789", "ssn_hash");
            Assert.Equal(a, b);
            Assert.All(a.ToCharArray(), ch => Assert.Contains(ch, "0123456789abcdef"));
        }

        [Fact]
        public void AccessNonreversibleRaises()
        {
            var c = CreateClient();
            var masked = c.Protect("123-45-6789", "ssn_mask");
            var ex = Assert.Throws<ArgumentException>(() => c.AccessByHeader(masked));
            Assert.Contains("No matching header", ex.Message);
        }

        [Fact]
        public void HeaderCollisionRaises()
        {
            var json = @"{
                ""configurations"": {
                    ""a"": { ""engine"": ""ff1"", ""key_ref"": ""k"", ""header"": ""ABC"" },
                    ""b"": { ""engine"": ""ff1"", ""key_ref"": ""k"", ""header"": ""ABC"" }
                },
                ""keys"": { ""k"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" } }
            }";
            var doc = JsonDocument.Parse(json);
            var ex = Assert.Throws<ArgumentException>(() => Cyphera.FromConfig(doc.RootElement));
            Assert.Contains("Header collision", ex.Message);
        }

        [Fact]
        public void HeaderRequiredRaises()
        {
            var json = @"{
                ""configurations"": { ""a"": { ""engine"": ""ff1"", ""key_ref"": ""k"" } },
                ""keys"": { ""k"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" } }
            }";
            var doc = JsonDocument.Parse(json);
            var ex = Assert.Throws<ArgumentException>(() => Cyphera.FromConfig(doc.RootElement));
            Assert.Contains("no header specified", ex.Message);
        }

        [Fact]
        public void UnicodePassthroughs()
        {
            var c = CreateClient();
            var protected_ = c.Protect("José123456", "ssn");
            var accessed = c.AccessByHeader(protected_);
            Assert.Equal("José123456", accessed);
        }

        [Fact]
        public void CrossLanguageVector()
        {
            // Must match: Java, Rust, Node, Python, Go all produce T01i6J-xF-07pX
            var c = CreateClient();
            var result = c.Protect("123-45-6789", "ssn");
            Assert.Equal("T01i6J-xF-07pX", result);
        }

        // ── New error condition: 2-arg Access on headered config ──

        [Fact]
        public void TwoArgAccessOnHeaderedConfigRaises()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123-45-6789", "ssn");
            // ssn has header_enabled=true; Access(value, "ssn") must error rather
            // than silently return garbage. Callers should use Access(value) so
            // the header identifies the configuration.
            var ex = Assert.Throws<ArgumentException>(() => c.Access(protected_, "ssn"));
            Assert.Contains("header_enabled=true", ex.Message);
            Assert.Contains("ssn", ex.Message);
        }
    }
}
