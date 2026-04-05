# Cyphera

Data obfuscation SDK for .NET. FPE, AES, masking, hashing.

```
dotnet add package Cyphera
```

```csharp
using Cyphera;

var cipher = FF1.Digits(key, tweak);
var encrypted = cipher.Encrypt("0123456789");
var decrypted = cipher.Decrypt(encrypted);
```

## Status

Early development. FF1 and FF3 engines with all NIST test vectors. Pure C#, no native deps.

## License

Apache 2.0
