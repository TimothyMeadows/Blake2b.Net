using PinnedMemory;

namespace Blake2b.Net.Examples;

public static class ByteArrayExample
{
    // WARNING: It's unsafe to output pinned memory as a string, even using bitconverter however for the sake of learning this is done below.
    // DO NOT DO THIS IN YOUR APPLICATION, you should store your pinned data in it's native form so it will remain locked, and pinned in place.
    public static void Run()
    {
        Console.WriteLine("[ByteArrayExample]");

        Hash();
        Mac();
    }

    private static void Hash()
    {
        // This is an example of hashing byte[] using PinnedMemory. This is the best method as it protects bytes during creation of the hash
        // and not just the output. It will also zero bytes after there written. However, raw byte[] is also accepted as shown in the commented version.
        var digest = new Blake2b();
        using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);

        // digest.UpdateBlock(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, 0, 11); // This may be exposed without being pinned.
        digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false),
            0, 11);
        digest.DoFinal(exampleHash, 0);

        Console.WriteLine(BitConverter.ToString(exampleHash.ToArray()));
    }

    private static void Mac()
    {
        // This is an example of hashing byte[] using PinnedMemory. This is the best method as it protects bytes during creation of the mac
        // and not just the output. It will also zero bytes after there written. However, raw byte[] is also accepted as shown in the commented version.
        var digest = new Blake2bMac(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77}, false));
        using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);

        // digest.UpdateBlock(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, 0, 11); // This may be exposed without being pinned.
        digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false),
            0, 11);
        digest.DoFinal(exampleHash, 0);

        Console.WriteLine(BitConverter.ToString(exampleHash.ToArray()));
    }
}
