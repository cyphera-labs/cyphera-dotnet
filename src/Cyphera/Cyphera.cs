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

        private readonly Dictionary<string, Configuration> _configurations = new();
        private readonly Dictionary<string, string> _headerIndex = new();
        private readonly Dictionary<string, byte[]> _keys = new();

        private Cyphera(JsonElement config)
        {
            LoadKeys(config);
            LoadConfigurations(config);
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
            var envPath = Environment.GetEnvironmentVariable("CYPHERA_CONFIG_FILE");
            if (!string.IsNullOrEmpty(envPath) && File.Exists(envPath))
                return FromFile(envPath);
            if (File.Exists("cyphera.json"))
                return FromFile("cyphera.json");
            if (File.Exists("/etc/cyphera/cyphera.json"))
                return FromFile("/etc/cyphera/cyphera.json");
            throw new FileNotFoundException(
                "No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json");
        }

        public static Cyphera FromFile(string path)
        {
            var json = File.ReadAllText(path);
            var doc = JsonDocument.Parse(json);
            return new Cyphera(doc.RootElement);
        }

        public string Protect(string value, string configurationName)
        {
            var configuration = GetConfiguration(configurationName);
            return configuration.Engine switch
            {
                "ff1" => ProtectFpe(value, configuration, false),
                "ff3" => ProtectFpe(value, configuration, true),
                "mask" => ProtectMask(value, configuration),
                "hash" => ProtectHash(value, configuration),
                _ => throw new ArgumentException($"Unknown engine: {configuration.Engine}")
            };
        }

        public string Access(string protectedValue, string? configurationName = null)
        {
            if (configurationName != null)
            {
                var configuration = GetConfiguration(configurationName);
                return AccessFpe(protectedValue, configuration, explicitConfiguration: true);
            }

            return AccessByHeader(protectedValue);
        }

        public string AccessByHeader(string protectedValue)
        {
            // Header-based lookup — longest headers first
            foreach (var header in _headerIndex.Keys.OrderByDescending(h => h.Length))
            {
                if (protectedValue.Length > header.Length && protectedValue.StartsWith(header))
                {
                    var configuration = GetConfiguration(_headerIndex[header]);
                    return AccessFpe(protectedValue, configuration);
                }
            }

            throw new ArgumentException("No matching header found. Use Access(value, configurationName) for values without a header.");
        }

        // ── FPE ──

        private string ProtectFpe(string value, Configuration configuration, bool isFF3)
        {
            var key = ResolveKey(configuration.KeyRef);
            var alphabet = configuration.Alphabet;

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

            if (configuration.HeaderEnabled && configuration.Header != null)
                return configuration.Header + result;
            return result;
        }

        private string AccessFpe(string protectedValue, Configuration configuration, bool explicitConfiguration = false)
        {
            if (configuration.Engine != "ff1" && configuration.Engine != "ff3")
                throw new ArgumentException($"Cannot reverse '{configuration.Engine}' — not reversible");

            var key = ResolveKey(configuration.KeyRef);
            var alphabet = configuration.Alphabet;

            var withoutHeader = protectedValue;
            if (!explicitConfiguration && configuration.HeaderEnabled && configuration.Header != null)
                withoutHeader = protectedValue[configuration.Header.Length..];

            var (encryptable, positions, chars) = ExtractPassthroughs(withoutHeader, alphabet);

            string decrypted;
            if (configuration.Engine == "ff3")
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

        private static string ProtectMask(string value, Configuration configuration)
        {
            if (string.IsNullOrEmpty(configuration.Pattern))
                throw new ArgumentException("Mask configuration requires 'pattern'");

            int len = value.Length;
            return configuration.Pattern switch
            {
                "last4" or "last_4" => new string('*', Math.Max(0, len - 4)) + value[^Math.Min(4, len)..],
                "last2" or "last_2" => new string('*', Math.Max(0, len - 2)) + value[^Math.Min(2, len)..],
                "first1" or "first_1" => value[..Math.Min(1, len)] + new string('*', Math.Max(0, len - 1)),
                "first3" or "first_3" => value[..Math.Min(3, len)] + new string('*', Math.Max(0, len - 3)),
                _ => new string('*', len) // "full" or default
            };
        }

        // ── Hash ──

        private string ProtectHash(string value, Configuration configuration)
        {
            var algo = configuration.Algorithm.Replace("-", "").ToLowerInvariant();
            var hashName = algo switch
            {
                "sha256" => HashAlgorithmName.SHA256,
                "sha384" => HashAlgorithmName.SHA384,
                "sha512" => HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {configuration.Algorithm}")
            };

            var data = Encoding.UTF8.GetBytes(value);

            if (!string.IsNullOrEmpty(configuration.KeyRef))
            {
                var key = ResolveKey(configuration.KeyRef);
                using var hmac = algo switch
                {
                    "sha256" => (HMAC)new HMACSHA256(key),
                    "sha384" => new HMACSHA384(key),
                    "sha512" => new HMACSHA512(key),
                    _ => throw new ArgumentException($"Unsupported hash algorithm: {configuration.Algorithm}")
                };
                return Convert.ToHexString(hmac.ComputeHash(data)).ToLowerInvariant();
            }

            using var hash = HashAlgorithm.Create(hashName.Name!)!;
            return Convert.ToHexString(hash.ComputeHash(data)).ToLowerInvariant();
        }

        // ── Helpers ──

        private Configuration GetConfiguration(string name)
        {
            if (!_configurations.TryGetValue(name, out var configuration))
                throw new ArgumentException($"Unknown configuration: {name}");
            return configuration;
        }

        private byte[] ResolveKey(string? keyRef)
        {
            if (string.IsNullOrEmpty(keyRef))
                throw new ArgumentException("No key_ref in configuration");
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

        private void LoadConfigurations(JsonElement root)
        {
            if (!root.TryGetProperty("configurations", out var configurationsEl)) return;
            foreach (var kv in configurationsEl.EnumerateObject())
            {
                var p = kv.Value;
                bool headerEnabled = !p.TryGetProperty("header_enabled", out var he) || he.GetBoolean();
                string? header = p.TryGetProperty("header", out var hv) ? hv.GetString() : null;

                if (headerEnabled && string.IsNullOrEmpty(header))
                    throw new ArgumentException($"Configuration '{kv.Name}' has header_enabled=true but no header specified");

                if (headerEnabled && header != null)
                {
                    if (_headerIndex.ContainsKey(header))
                        throw new ArgumentException($"Header collision: '{header}' used by both '{_headerIndex[header]}' and '{kv.Name}'");
                    _headerIndex[header] = kv.Name;
                }

                _configurations[kv.Name] = new Configuration
                {
                    Engine = GetStr(p, "engine") ?? "ff1",
                    Alphabet = ResolveAlphabet(GetStr(p, "alphabet")),
                    KeyRef = GetStr(p, "key_ref"),
                    Header = header,
                    HeaderEnabled = headerEnabled,
                    Pattern = GetStr(p, "pattern"),
                    Algorithm = GetStr(p, "algorithm") ?? "sha256",
                };
            }
        }

        private static string? GetStr(JsonElement el, string prop)
        {
            return el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        }

        private class Configuration
        {
            public string Engine { get; init; } = "ff1";
            public string Alphabet { get; init; } = "";
            public string? KeyRef { get; init; }
            public string? Header { get; init; }
            public bool HeaderEnabled { get; init; } = true;
            public string? Pattern { get; init; }
            public string Algorithm { get; init; } = "sha256";
        }
    }
}
