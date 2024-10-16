using PinnedMemory;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Blake2b.Net.Examples;

public static class StringExample
{
    // WARNING: It's unsafe to output pinned memory as a string, even using bitconverter however for the sake of learning this is done below.
    // DO NOT DO THIS IN YOUR APPLICATION, you should store your pinned data in it's native form so it will remain locked, and pinned in place.
    public static void Run()
    {
        // Strings are very unsafe to store passwords, or keys in. This is because strings in .NET will always be subject to garbage collection
        // which means they can always be dumped out of memory onto disk through various methods, and exploits. However, especially when dealing
        // with website logins through forms. It's almost impossible to avoid the risk completely. Below are some examples of best dealing with 
        // these conditions. Ultimately however, if you can record your secure input directly in byte, char, or SecureString you will always be better off.
        Console.WriteLine("[StringExample]");

        Hash();
        Mac();
    }

    public static void Hash()
    {
        var digest = new Blake2b();

        // This is a common, but could be unsafe example of dealing with strings from a form using text encoding.
        using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
        var unsafeCaw = "caw caw caw"; // this is unsafe because string's can't be pinned and are subject to garbage collection, and being written to disk (pagefile).
        var caw = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(unsafeCaw), false); // this is now safe but ONLY the variable caw, unsafeCaw is STILL exposed.
        unsafeCaw = string.Empty; // unsafeCaw COULD STILL exposed even tho we set it to empty because this depends on garbage collection getting around to clearing it.
        digest.UpdateBlock(caw, 0, caw.Length);
        digest.DoFinal(exampleHash, 0);

        Console.WriteLine(BitConverter.ToString(exampleHash.ToArray()));

        // This is a more uncommon but should be safer example of how to use strings with SecureString for input.
        using var exampleHash2 = new PinnedMemory<byte>(new byte[digest.GetLength()]);

        var secureCaw = new SecureString();
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.AppendChar(' ');
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.AppendChar(' ');
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.MakeReadOnly();

        using var pinnedCaw = new PinnedMemory<char>(new char[secureCaw.Length]);
        var cawPointer = Marshal.SecureStringToBSTR(secureCaw);
        for (var i = 0; i <= secureCaw.Length - 1; i++)
        {
            var c = (char)Marshal.ReadByte(cawPointer, i * 2);
            pinnedCaw[i] = c;
        }

        using var pinnedCawBytes = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(pinnedCaw.ToArray()), false);
        digest.UpdateBlock(pinnedCawBytes, 0, secureCaw.Length);
        digest.DoFinal(exampleHash2, 0);
        Console.WriteLine(BitConverter.ToString(exampleHash2.ToArray()));
    }

    public static void Mac()
    {
        var digest = new Blake2bMac(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77}, false));

        // This is a common, but could be unsafe example of dealing with strings from a form using text encoding.
        using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
        var unsafeCaw = "caw caw caw"; // this is unsafe because string's can't be pinned and are subject to garbage collection, and being written to disk (pagefile).
        var caw = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(unsafeCaw), false); // this is now safe but ONLY the variable caw, unsafeCaw is STILL exposed.
        unsafeCaw = string.Empty; // unsafeCaw COULD STILL exposed even tho we set it to empty because this depends on garbage collection getting around to clearing it.
        digest.UpdateBlock(caw, 0, caw.Length);
        digest.DoFinal(exampleHash, 0);

        Console.WriteLine(BitConverter.ToString(exampleHash.ToArray()));

        // This is a more uncommon but should be safer example of how to use strings with SecureString for input.
        using var exampleHash2 = new PinnedMemory<byte>(new byte[digest.GetLength()]);

        var secureCaw = new SecureString();
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.AppendChar(' ');
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.AppendChar(' ');
        secureCaw.AppendChar('c');
        secureCaw.AppendChar('a');
        secureCaw.AppendChar('w');
        secureCaw.MakeReadOnly();

        using var pinnedCaw = new PinnedMemory<char>(new char[secureCaw.Length]);
        var cawPointer = Marshal.SecureStringToBSTR(secureCaw);
        for (var i = 0; i <= secureCaw.Length - 1; i++)
        {
            var c = (char)Marshal.ReadByte(cawPointer, i * 2);
            pinnedCaw[i] = c;
        }

        using var pinnedCawBytes = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(pinnedCaw.ToArray()), false);
        digest.UpdateBlock(pinnedCawBytes, 0, secureCaw.Length);
        digest.DoFinal(exampleHash2, 0);
        Console.WriteLine(BitConverter.ToString(exampleHash2.ToArray()));
    }
}
