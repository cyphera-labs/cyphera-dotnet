using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cyphera
{
    public class Cyphera
    {
        private static readonly Dictionary<string, string> Alphabets = new()
        {
            ["digits"] = "0123456789",
            ["alpha_lower"] = "abcdefghijklmnopqrstuvwxyz",
            ["alpha_upper"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ["alpha"] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ["alphanumeric"] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        };

        private readonly Dictionary<string, PolicyEntry> _policies = new();
        private readonly Dictionary<string, string> _tagIndex = new();
        private readonly Dictionary<string, byte[]> _keys = new();

        private Cyphera(JsonElement config)
        {
            LoadKeys(config);
            LoadPolicies(config);
        }

        public static Cyphera FromConfig(JsonElement config) => new Cyphera(config);

        public static Cyphera FromConfig(Dictionary<string, object> config)
        {
            var json = JsonSerializer.Serialize(config);
            var doc = JsonDocument.Parse(json);
            return new Cyphera(doc.RootElement);
        }

        public static Cyphera Load()
        {
            var envPath = Environment.GetEnvironmentVariable("CYPHERA_POLICY_FILE");
            if (!string.IsNullOrEmpty(envPath) && File.Exists(envPath))
                return FromFile(envPath);
            if (File.Exists("cyphera.json"))
                return FromFile("cyphera.json");
            if (File.Exists("/etc/cyphera/cyphera.json"))
                return FromFile("/etc/cyphera/cyphera.json");
            throw new FileNotFoundException(
                "No policy file found. Checked: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json");
        }

        public static Cyphera FromFile(string path)
        {
            var json = File.ReadAllText(path);
            var doc = JsonDocument.Parse(json);
            return new Cyphera(doc.RootElement);
        }

        public string Protect(string value, string policyName)
        {
            var policy = GetPolicy(policyName);
            return policy.Engine switch
            {
                "ff1" => ProtectFpe(value, policy, false),
                "ff3" => ProtectFpe(value, policy, true),
                "mask" => ProtectMask(value, policy),
                "hash" => ProtectHash(value, policy),
                _ => throw new ArgumentException($"Unknown engine: {policy.Engine}")
            };
        }

        public string Access(string protectedValue, string? policyName = null)
        {
            if (policyName != null)
            {
                var policy = GetPolicy(policyName);
                return AccessFpe(protectedValue, policy, explicitPolicy: true);
            }

            // Tag-based lookup — longest tags first
            foreach (var tag in _tagIndex.Keys.OrderByDescending(t => t.Length))
            {
                if (protectedValue.Length > tag.Length && protectedValue.StartsWith(tag))
                {
                    var policy = GetPolicy(_tagIndex[tag]);
                    return AccessFpe(protectedValue, policy);
                }
            }

            throw new ArgumentException("No matching tag found. Use Access(value, policyName) for untagged values.");
        }

        // ── FPE ──

        private string ProtectFpe(string value, PolicyEntry policy, bool isFF3)
        {
            var key = ResolveKey(policy.KeyRef);
            var alphabet = policy.Alphabet;

            var (encryptable, positions, chars) = ExtractPassthroughs(value, alphabet);
            if (encryptable.Length == 0)
                throw new ArgumentException("No encryptable characters in input");

            string encrypted;
            if (isFF3)
            {
                var cipher = new FF3(key, new byte[8], alphabet);
                encrypted = cipher.Encrypt(encryptable);
            }
            else
            {
                var cipher = new FF1(key, Array.Empty<byte>(), alphabet);
                encrypted = cipher.Encrypt(encryptable);
            }

            var result = ReinsertPassthroughs(encrypted, positions, chars);

            if (policy.TagEnabled && policy.Tag != null)
                return policy.Tag + result;
            return result;
        }

        private string AccessFpe(string protectedValue, PolicyEntry policy, bool explicitPolicy = false)
        {
            if (policy.Engine != "ff1" && policy.Engine != "ff3")
                throw new ArgumentException($"Cannot reverse '{policy.Engine}' — not reversible");

            var key = ResolveKey(policy.KeyRef);
            var alphabet = policy.Alphabet;

            var withoutTag = protectedValue;
            if (!explicitPolicy && policy.TagEnabled && policy.Tag != null)
                withoutTag = protectedValue[policy.Tag.Length..];

            var (encryptable, positions, chars) = ExtractPassthroughs(withoutTag, alphabet);

            string decrypted;
            if (policy.Engine == "ff3")
            {
                var cipher = new FF3(key, new byte[8], alphabet);
                decrypted = cipher.Decrypt(encryptable);
            }
            else
            {
                var cipher = new FF1(key, Array.Empty<byte>(), alphabet);
                decrypted = cipher.Decrypt(encryptable);
            }

            return ReinsertPassthroughs(decrypted, positions, chars);
        }

        // ── Mask ──

        private static string ProtectMask(string value, PolicyEntry policy)
        {
            if (string.IsNullOrEmpty(policy.Pattern))
                throw new ArgumentException("Mask policy requires 'pattern'");

            int len = value.Length;
            return policy.Pattern switch
            {
                "last4" or "last_4" => new string('*', Math.Max(0, len - 4)) + value[^Math.Min(4, len)..],
                "last2" or "last_2" => new string('*', Math.Max(0, len - 2)) + value[^Math.Min(2, len)..],
                "first1" or "first_1" => value[..Math.Min(1, len)] + new string('*', Math.Max(0, len - 1)),
                "first3" or "first_3" => value[..Math.Min(3, len)] + new string('*', Math.Max(0, len - 3)),
                _ => new string('*', len) // "full" or default
            };
        }

        // ── Hash ──

        private string ProtectHash(string value, PolicyEntry policy)
        {
            var algo = policy.Algorithm.Replace("-", "").ToLowerInvariant();
            var hashName = algo switch
            {
                "sha256" => HashAlgorithmName.SHA256,
                "sha384" => HashAlgorithmName.SHA384,
                "sha512" => HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {policy.Algorithm}")
            };

            var data = Encoding.UTF8.GetBytes(value);

            if (!string.IsNullOrEmpty(policy.KeyRef))
            {
                var key = ResolveKey(policy.KeyRef);
                using var hmac = algo switch
                {
                    "sha256" => (HMAC)new HMACSHA256(key),
                    "sha384" => new HMACSHA384(key),
                    "sha512" => new HMACSHA512(key),
                    _ => throw new ArgumentException($"Unsupported hash algorithm: {policy.Algorithm}")
                };
                return Convert.ToHexString(hmac.ComputeHash(data)).ToLowerInvariant();
            }

            using var hash = HashAlgorithm.Create(hashName.Name!)!;
            return Convert.ToHexString(hash.ComputeHash(data)).ToLowerInvariant();
        }

        // ── Helpers ──

        private PolicyEntry GetPolicy(string name)
        {
            if (!_policies.TryGetValue(name, out var policy))
                throw new ArgumentException($"Unknown policy: {name}");
            return policy;
        }

        private byte[] ResolveKey(string? keyRef)
        {
            if (string.IsNullOrEmpty(keyRef))
                throw new ArgumentException("No key_ref in policy");
            if (!_keys.TryGetValue(keyRef, out var key))
                throw new ArgumentException($"Unknown key: {keyRef}");
            return key;
        }

        private static (string encryptable, List<int> positions, List<char> chars) ExtractPassthroughs(string value, string alphabet)
        {
            var sb = new StringBuilder();
            var positions = new List<int>();
            var chars = new List<char>();
            for (int i = 0; i < value.Length; i++)
            {
                if (alphabet.Contains(value[i]))
                    sb.Append(value[i]);
                else
                {
                    positions.Add(i);
                    chars.Add(value[i]);
                }
            }
            return (sb.ToString(), positions, chars);
        }

        private static string ReinsertPassthroughs(string encrypted, List<int> positions, List<char> chars)
        {
            var result = new List<char>(encrypted);
            for (int i = 0; i < positions.Count; i++)
            {
                int pos = positions[i];
                if (pos <= result.Count)
                    result.Insert(pos, chars[i]);
                else
                    result.Add(chars[i]);
            }
            return new string(result.ToArray());
        }

        private static string ResolveAlphabet(string? name)
        {
            if (string.IsNullOrEmpty(name)) return Alphabets["alphanumeric"];
            return Alphabets.TryGetValue(name, out var alpha) ? alpha : name;
        }

        private static readonly HashSet<string> CloudSources = new() { "aws-kms", "gcp-kms", "azure-kv", "vault" };

        private void LoadKeys(JsonElement root)
        {
            if (!root.TryGetProperty("keys", out var keysEl)) return;
            foreach (var kv in keysEl.EnumerateObject())
            {
                var name = kv.Name;
                if (kv.Value.ValueKind == JsonValueKind.String)
                {
                    _keys[name] = Convert.FromHexString(kv.Value.GetString()!);
                }
                else if (kv.Value.TryGetProperty("material", out var mat))
                {
                    _keys[name] = Convert.FromHexString(mat.GetString()!);
                }
                else if (kv.Value.TryGetProperty("source", out var src))
                {
                    _keys[name] = ResolveKeySource(name, src.GetString()!, kv.Value);
                }
                else
                {
                    throw new ArgumentException($"Key '{name}' must have either 'material' or 'source'");
                }
            }
        }

        private static byte[] ResolveKeySource(string name, string source, JsonElement config)
        {
            if (source == "env")
            {
                var varName = config.GetProperty("var").GetString()
                    ?? throw new ArgumentException($"Key '{name}': source 'env' requires 'var' field");
                var val = Environment.GetEnvironmentVariable(varName)
                    ?? throw new ArgumentException($"Key '{name}': environment variable '{varName}' is not set");
                var encoding = config.TryGetProperty("encoding", out var enc) ? enc.GetString() : "hex";
                return encoding == "base64" ? Convert.FromBase64String(val) : Convert.FromHexString(val);
            }

            if (source == "file")
            {
                var path = config.GetProperty("path").GetString()
                    ?? throw new ArgumentException($"Key '{name}': source 'file' requires 'path' field");
                var raw = File.ReadAllText(path).Trim();
                var encoding = config.TryGetProperty("encoding", out var enc) ? enc.GetString()
                    : (path.EndsWith(".b64") || path.EndsWith(".base64") ? "base64" : "hex");
                return encoding == "base64" ? Convert.FromBase64String(raw) : Convert.FromHexString(raw);
            }

            if (CloudSources.Contains(source))
            {
                var resolverType = Type.GetType("Cyphera.Keychain.KeychainResolver, Cyphera.Keychain");
                if (resolverType == null)
                    throw new InvalidOperationException(
                        $"Key '{name}' requires source '{source}' but Cyphera.Keychain is not installed.\n" +
                        "Install it: dotnet add package Cyphera.Keychain");
                var method = resolverType.GetMethod("Resolve", new[] { typeof(string), typeof(JsonElement) })!;
                return (byte[])method.Invoke(null, new object[] { source, config })!;
            }

            throw new ArgumentException($"Key '{name}': unknown source '{source}'. Valid: env, file, {string.Join(", ", CloudSources)}");
        }

        private void LoadPolicies(JsonElement root)
        {
            if (!root.TryGetProperty("policies", out var policiesEl)) return;
            foreach (var kv in policiesEl.EnumerateObject())
            {
                var p = kv.Value;
                bool tagEnabled = !p.TryGetProperty("tag_enabled", out var te) || te.GetBoolean();
                string? tag = p.TryGetProperty("tag", out var tv) ? tv.GetString() : null;

                if (tagEnabled && string.IsNullOrEmpty(tag))
                    throw new ArgumentException($"Policy '{kv.Name}' has tag_enabled=true but no tag specified");

                if (tagEnabled && tag != null)
                {
                    if (_tagIndex.ContainsKey(tag))
                        throw new ArgumentException($"Tag collision: '{tag}' used by both '{_tagIndex[tag]}' and '{kv.Name}'");
                    _tagIndex[tag] = kv.Name;
                }

                _policies[kv.Name] = new PolicyEntry
                {
                    Engine = GetStr(p, "engine") ?? "ff1",
                    Alphabet = ResolveAlphabet(GetStr(p, "alphabet")),
                    KeyRef = GetStr(p, "key_ref"),
                    Tag = tag,
                    TagEnabled = tagEnabled,
                    Pattern = GetStr(p, "pattern"),
                    Algorithm = GetStr(p, "algorithm") ?? "sha256",
                };
            }
        }

        private static string? GetStr(JsonElement el, string prop)
        {
            return el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        }

        private class PolicyEntry
        {
            public string Engine { get; init; } = "ff1";
            public string Alphabet { get; init; } = "";
            public string? KeyRef { get; init; }
            public string? Tag { get; init; }
            public bool TagEnabled { get; init; } = true;
            public string? Pattern { get; init; }
            public string Algorithm { get; init; } = "sha256";
        }
    }
}
