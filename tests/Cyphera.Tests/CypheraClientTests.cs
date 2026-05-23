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
            var accessed = c.Access(protected_);
            Assert.Equal("123456789", accessed);
        }

        [Fact]
        public void ProtectAccessWithPassthroughs()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123-45-6789", "ssn");
            Assert.Contains("-", protected_);
            var accessed = c.Access(protected_);
            Assert.Equal("123-45-6789", accessed);
        }

        [Fact]
        public void UnheaderedDigitsRoundtrip()
        {
            var c = CreateClient();
            var protected_ = c.Protect("123456789", "ssn_digits");
            Assert.Equal(9, protected_.Length);
            // ssn_digits has header_enabled=false, so the 2-arg Access overload
            // (escape hatch) is the way to round-trip without a header to key off.
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
            // ssn_mask has header_enabled=false, so Access() can't find a header
            // and reports the no-matching-header error.
            var ex = Assert.Throws<ArgumentException>(() => c.Access(masked));
            Assert.Equal("no matching header found", ex.Message);
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
            Assert.Equal("configuration error: header collision", ex.Message);
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
            Assert.Equal("configuration error: header must be specified", ex.Message);
        }

        [Fact]
        public void UnicodePassthroughs()
        {
            var c = CreateClient();
            var protected_ = c.Protect("José123456", "ssn");
            var accessed = c.Access(protected_);
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

        // ── 2-arg Access overload (escape hatch) ──

        [Fact]
        public void TwoArgAccessOnIrreversibleConfigRaises()
        {
            var c = CreateClient();
            // The 2-arg escape hatch is permissive about header_enabled but
            // still must refuse mask/hash configurations — those are one-way.
            var masked = c.Protect("123-45-6789", "ssn_mask");
            var ex = Assert.Throws<ArgumentException>(() => c.Access(masked, "ssn_mask"));
            Assert.Equal("cannot reverse 'ssn_mask' — mask is irreversible", ex.Message);
        }

        // ── Strict FF3 / FF3-1 tweak (no silent zero-fill) ──

        [Fact]
        public void Ff3MissingTweakRaises()
        {
            var json = @"{
                ""configurations"": {
                    ""ff3_no_tweak"": { ""engine"": ""ff3"", ""alphabet"": ""digits"", ""key_ref"": ""k"", ""header"": ""T03"" }
                },
                ""keys"": { ""k"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" } }
            }";
            var doc = JsonDocument.Parse(json);
            var c = Cyphera.FromConfig(doc.RootElement);
            var ex = Assert.Throws<ArgumentException>(() => c.Protect("123456789", "ff3_no_tweak"));
            Assert.Equal(
                "configuration 'ff3_no_tweak' is missing required 'tweak' (FF3 needs 8 bytes)",
                ex.Message);
        }

        [Fact]
        public void Ff31MissingTweakRaises()
        {
            var json = @"{
                ""configurations"": {
                    ""ff31_no_tweak"": { ""engine"": ""ff31"", ""alphabet"": ""digits"", ""key_ref"": ""k"", ""header"": ""T04"" }
                },
                ""keys"": { ""k"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" } }
            }";
            var doc = JsonDocument.Parse(json);
            var c = Cyphera.FromConfig(doc.RootElement);
            var ex = Assert.Throws<ArgumentException>(() => c.Protect("123456789", "ff31_no_tweak"));
            Assert.Equal(
                "configuration 'ff31_no_tweak' is missing required 'tweak' (FF3-1 needs 7 bytes)",
                ex.Message);
        }

        [Fact]
        public void Ff3WithExplicitTweakRoundtrips()
        {
            var json = @"{
                ""configurations"": {
                    ""ff3_ok"": { ""engine"": ""ff3"", ""alphabet"": ""digits"", ""key_ref"": ""k"", ""header"": ""T05"", ""tweak"": ""D8E7920AFA330A73"" }
                },
                ""keys"": { ""k"": { ""material"": ""2B7E151628AED2A6ABF7158809CF4F3C"" } }
            }";
            var doc = JsonDocument.Parse(json);
            var c = Cyphera.FromConfig(doc.RootElement);
            var protected_ = c.Protect("123456789", "ff3_ok");
            Assert.NotEqual("123456789", protected_);
            Assert.Equal("123456789", c.Access(protected_));
        }

        [Fact]
        public void Ff1MissingTweakStillWorks()
        {
            // FF1 tweak stays optional per NIST SP 800-38G.
            var c = CreateClient();
            var protected_ = c.Protect("123456789", "ssn"); // ssn is ff1 with no tweak
            Assert.Equal("123456789", c.Access(protected_));
        }
    }
}
