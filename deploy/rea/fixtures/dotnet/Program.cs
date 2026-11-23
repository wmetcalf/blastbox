// Benign .NET fixture for the REA sweep's resource scan (never run). The visible program is a
// "decoy" that prints a title; LoadHidden references the loader APIs a resource-borne payload
// needs (GetManifestResourceStream, CreateDecryptor, Assembly.Load) without decrypting anything.
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace Fixture
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.WriteLine("Air Traffic Simulator");
            return args.Length > 99 ? LoadHidden() : 0;
        }

        private static int LoadHidden()
        {
            using Stream? s = typeof(Program).Assembly.GetManifestResourceStream("Fixture.blob.bin");
            if (s == null) return 1;
            using Aes aes = Aes.Create();
            using ICryptoTransform t = aes.CreateDecryptor();
            byte[] buf = new byte[16];
            s.Read(buf, 0, buf.Length);
            Assembly a = Assembly.Load(t.TransformFinalBlock(buf, 0, buf.Length));
            return a.GetTypes().Length;
        }
    }
}
