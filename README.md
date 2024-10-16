
# Blake2b.Net
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Blake2b.NetCore.svg)](https://www.nuget.org/packages/Blake2b.NetCore/)

Blake2b.Net provides an implementation of the cryptographic hash and MAC functions of the [BLAKE2b](https://tools.ietf.org/html/draft-saarinen-blake2-02) algorithm, optimized for SIMD hardware instructions and [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory) support.

## Features
- Supports cryptographic hash generation using BLAKE2b.
- MAC (Message Authentication Code) functionality with key and salt.
- Optimized for SIMD instructions to ensure fast performance on supported hardware.
- Secure key and buffer management with PinnedMemory to avoid sensitive data leaks.

## Installation

You can install the package via NuGet:

### .NET CLI
```bash
dotnet add package Blake2b.Net
```

### Package Manager
```bash
Install-Package Blake2b.Net
```

### NuGet Website
You can also search for and install the package via the NuGet UI or from the following link:
[Blake2b.Net on NuGet](https://www.nuget.org/packages/Blake2b.Net/)

## Usage Examples

### Hashing Example:
```csharp
var digest = new Blake2b();
using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11);
digest.DoFinal(exampleHash, 0);
```

### MAC Example:
```csharp
var digest = new Blake2bMac(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77}, false));
using var exampleHash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11);
digest.DoFinal(exampleHash, 0);
```

## API Documentation

### Constructors

#### `Blake2b(int digestSize = 512)`
- Initializes a new instance of the `Blake2b` class with the specified digest size.
- Supported digest sizes: 160, 256, 384, 512 bits.
- Default size: 512 bits.

#### `Blake2bMac(PinnedMemory<byte> key)`
- Initializes a new instance of the `Blake2bMac` class with the specified key for MAC generation.
- The key should be provided in the form of a `PinnedMemory<byte>` object.

#### `Blake2bMac(PinnedMemory<byte> key, byte[] salt, int digestSize = 512)`
- Initializes a new instance of the `Blake2bMac` class with the specified key, salt, and digest size.
- Supported digest sizes: 160, 256, 384, 512 bits.
- Default size: 512 bits.
- The salt must be 16 bytes long.

### Methods

#### `void Update(byte b)`
- Updates the message digest with a single byte.

#### `void UpdateBlock(PinnedMemory<byte> message, int offset, int len)`
- Updates the message digest with a pinned memory byte array.

#### `void UpdateBlock(byte[] message, int offset, int len)`
- Updates the message digest with a regular byte array.

#### `void DoFinal(PinnedMemory<byte> output, int outOffset)`
- Produces the final digest value and outputs it to the specified `PinnedMemory<byte>` buffer.

#### `void Reset()`
- Resets the digest to its initial state for further processing.
- The key and salt remain until the object is disposed.

#### `void Dispose()`
- Clears the key and salt, resets the digest to its initial state, and releases resources.

## Performance Considerations

The BLAKE2b algorithm is optimized for modern SIMD instructions (such as AVX and SSE) to provide enhanced performance on supported hardware. This ensures that hashing and MAC operations are processed efficiently, even with large datasets.

## Security Considerations

This library utilizes `PinnedMemory` to ensure that sensitive data such as keys and message buffers are not moved by the garbage collector, reducing the risk of memory leaks. Ensure that you call `Dispose()` on any `PinnedMemory` object or classes that use it to securely clear and free memory after use.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
