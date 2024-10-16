using PinnedMemory;
using System.Numerics;

namespace Blake2b.Net
{
    public class Blake2bMac : IDisposable
    {
        private static readonly ulong[] Blake2BIv =
        {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
            0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
            0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
        };

        private static readonly byte[,] Blake2BSigma =
        {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        private const int Rounds = 12;
        private const int BlockLengthBytes = 128;

        private readonly int _digestLength;
        private readonly int _keyLength = 0;
        private readonly byte[]? _salt = null;
        private readonly PinnedMemory<byte> _key;
        private readonly PinnedMemory<byte> _bufferPin;
        private readonly PinnedMemory<byte> _simdTempBuffer;
        private int _bufferPos = 0;

        private readonly ulong[] _internalState = new ulong[16];
        private ulong[]? _chainValue = null;

        private ulong t0 = 0UL;
        private ulong t1 = 0UL;
        private ulong f0 = 0UL;

        public Blake2bMac(PinnedMemory<byte> key)
        {
            _bufferPin = new PinnedMemory<byte>(new byte[BlockLengthBytes]);
            _simdTempBuffer = new PinnedMemory<byte>(new byte[Vector<byte>.Count]);

            if (key != null)
            {
                _key = key;
                if (_key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                _keyLength = _key.Length;
                Array.Copy(_key.ToArray(), 0, _bufferPin.ToArray(), 0, _keyLength);
                _bufferPos = BlockLengthBytes;
            }
            _digestLength = 64;
            Init();
        }

        public Blake2bMac(PinnedMemory<byte> key, byte[] salt, int digestLength = 512)
        {
            if (digestLength < 1 || digestLength > 64)
                throw new ArgumentException("Invalid digest length (required: 1 - 64)");

            this._digestLength = digestLength;
            _bufferPin = new PinnedMemory<byte>(new byte[BlockLengthBytes]);
            _simdTempBuffer = new PinnedMemory<byte>(new byte[Vector<byte>.Count]);

            if (salt != null)
            {
                if (salt.Length != 16)
                    throw new ArgumentException("salt length must be exactly 16 bytes");

                this._salt = new byte[16];
                Array.Copy(salt, 0, this._salt, 0, salt.Length);
            }

            if (key != null)
            {
                if (key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                _key = key;
                _keyLength = key.Length;
                _bufferPos = BlockLengthBytes;
            }

            Init();
        }

        private void Init()
        {
            if (_chainValue == null)
            {
                _chainValue = new ulong[8];
                _chainValue[0] = Blake2BIv[0] ^ (ulong)(_digestLength | (_keyLength << 8) | 0x1010000);
                _chainValue[1] = Blake2BIv[1];
                _chainValue[2] = Blake2BIv[2];
                _chainValue[3] = Blake2BIv[3];
                _chainValue[4] = Blake2BIv[4];
                _chainValue[5] = Blake2BIv[5];
                if (_salt != null)
                {
                    _chainValue[4] ^= LE_To_UInt64(_salt, 0);
                    _chainValue[5] ^= LE_To_UInt64(_salt, 8);
                }
                _chainValue[6] = Blake2BIv[6];
                _chainValue[7] = Blake2BIv[7];
            }
        }

        private void InitializeInternalState()
        {
            if (_chainValue == null)
                return;

            Array.Copy(_chainValue, 0, _internalState, 0, _chainValue.Length);
            Array.Copy(Blake2BIv, 0, _internalState, _chainValue.Length, 4);
            _internalState[12] = t0 ^ Blake2BIv[4];
            _internalState[13] = t1 ^ Blake2BIv[5];
            _internalState[14] = f0 ^ Blake2BIv[6];
            _internalState[15] = Blake2BIv[7];
        }

        public virtual void Update(byte b)
        {
            try
            {
                var remainingLength = BlockLengthBytes - _bufferPos;
                if (remainingLength == 0)
                {
                    t0 += BlockLengthBytes;
                    if (t0 == 0)
                    {
                        t1++;
                    }
                    Compress(_bufferPin.ToArray(), 0);
                    ClearBuffer();
                    _bufferPin.ToArray()[0] = b;
                    _bufferPos = 1;
                }
                else
                {
                    _bufferPin.ToArray()[_bufferPos] = b;
                    _bufferPos++;
                }
            }
            catch (Exception)
            {
                ClearBuffer();
                throw;
            }
        }

        public virtual void UpdateBlock(PinnedMemory<byte> message, int offset, int len)
        {
            try
            {
                UpdateBlock(message.ToArray(), offset, len);
            }
            finally
            {
                message.Dispose();
            }
        }

        public virtual void UpdateBlock(byte[] message, int offset, int len)
        {
            try
            {
                if (message == null || len == 0)
                    return;

                var remainingLength = BlockLengthBytes - _bufferPos;

                if (_bufferPos != 0)
                {
                    if (remainingLength < len)
                    {
                        Array.Copy(message, offset, _bufferPin.ToArray(), _bufferPos, remainingLength);
                        t0 += BlockLengthBytes;
                        if (t0 == 0)
                        {
                            t1++;
                        }
                        Compress(_bufferPin.ToArray(), 0);
                        _bufferPos = 0;
                        ClearBuffer();
                        offset += remainingLength;
                        len -= remainingLength;
                    }
                    else
                    {
                        Array.Copy(message, offset, _bufferPin.ToArray(), _bufferPos, len);
                        _bufferPos += len;
                        return;
                    }
                }

                int messagePos = offset;
                var blockWiseLastPos = offset + len - BlockLengthBytes;

                while (blockWiseLastPos >= messagePos + Vector<byte>.Count)
                {
                    var vector = new Vector<byte>(message, messagePos);
                    messagePos += Vector<byte>.Count;
                }

                int remaining = offset + len - messagePos;
                if (remaining > 0)
                {
                    Array.Copy(message, messagePos, _bufferPin.ToArray(), 0, remaining);
                    _bufferPos += remaining;
                }
            }
            catch (Exception)
            {
                ClearBuffer();
                throw;
            }
        }

        public virtual void DoFinal(PinnedMemory<byte> output, int outOffset)
        {
            try
            {
                f0 = 0xFFFFFFFFFFFFFFFFUL;
                t0 += (ulong)_bufferPos;
                if (_bufferPos > 0 && t0 == 0)
                {
                    t1++;
                }
                Compress(_bufferPin.ToArray(), 0);
                ClearBuffer();
                Array.Clear(_internalState, 0, _internalState.Length);

                for (var i = 0; i < _chainValue.Length && (i * 8 < _digestLength); i++)
                {
                    var bytes = UInt64_To_LE(_chainValue[i]);

                    if (i * 8 < _digestLength - 8)
                    {
                        Array.Copy(bytes, 0, output.ToArray(), outOffset + i * 8, 8);
                    }
                    else
                    {
                        int remainingLength = _digestLength - (i * 8);
                        if (remainingLength > 0)
                        {
                            Array.Copy(bytes, 0, output.ToArray(), outOffset + i * 8, remainingLength);
                        }
                    }
                }

                Array.Clear(_chainValue, 0, _chainValue.Length);
            }
            catch (Exception)
            {
                ClearBuffer();
                throw;
            }
            finally
            {
                Reset();
            }
        }

        public virtual void Reset()
        {
            try
            {
                _bufferPos = 0;
                f0 = 0L;
                t0 = 0L;
                t1 = 0L;
                _chainValue = null;
                ClearBuffer();

                if (_key != null)
                {
                    Array.Copy(_key.ToArray(), 0, _bufferPin.ToArray(), 0, _key.Length);
                    _bufferPos = BlockLengthBytes;
                }
                Init();
            }
            catch (Exception)
            {
                ClearBuffer();
                throw;
            }
        }

        private void Compress(byte[] message, int messagePos)
        {
            try
            {
                InitializeInternalState();

                var m = new ulong[16];
                for (var j = 0; j < 16; j++)
                {
                    m[j] = LE_To_UInt64(message, messagePos + j * 8);
                }

                for (var round = 0; round < Rounds; round++)
                {
                    G(m[Blake2BSigma[round, 0]], m[Blake2BSigma[round, 1]], 0, 4, 8, 12);
                    G(m[Blake2BSigma[round, 2]], m[Blake2BSigma[round, 3]], 1, 5, 9, 13);
                    G(m[Blake2BSigma[round, 4]], m[Blake2BSigma[round, 5]], 2, 6, 10, 14);
                    G(m[Blake2BSigma[round, 6]], m[Blake2BSigma[round, 7]], 3, 7, 11, 15);
                    G(m[Blake2BSigma[round, 8]], m[Blake2BSigma[round, 9]], 0, 5, 10, 15);
                    G(m[Blake2BSigma[round, 10]], m[Blake2BSigma[round, 11]], 1, 6, 11, 12);
                    G(m[Blake2BSigma[round, 12]], m[Blake2BSigma[round, 13]], 2, 7, 8, 13);
                    G(m[Blake2BSigma[round, 14]], m[Blake2BSigma[round, 15]], 3, 4, 9, 14);
                }

                for (var offset = 0; offset < _chainValue.Length; offset++)
                {
                    _chainValue[offset] ^= _internalState[offset] ^ _internalState[offset + 8];
                }
            }
            catch (Exception)
            {
                ClearBuffer();
                throw;
            }
        }

        private void G(ulong m1, ulong m2, int posA, int posB, int posC, int posD)
        {
            _internalState[posA] = _internalState[posA] + _internalState[posB] + m1;
            _internalState[posD] = Rotr64(_internalState[posD] ^ _internalState[posA], 32);
            _internalState[posC] = _internalState[posC] + _internalState[posD];
            _internalState[posB] = Rotr64(_internalState[posB] ^ _internalState[posC], 24);
            _internalState[posA] = _internalState[posA] + _internalState[posB] + m2;
            _internalState[posD] = Rotr64(_internalState[posD] ^ _internalState[posA], 16);
            _internalState[posC] = _internalState[posC] + _internalState[posD];
            _internalState[posB] = Rotr64(_internalState[posB] ^ _internalState[posC], 63);
        }

        private static ulong Rotr64(ulong x, int rot)
        {
            return x >> rot | x << -rot;
        }

        public virtual int GetLength()
        {
            return _digestLength;
        }

        public virtual int GetBlockSize()
        {
            return BlockLengthBytes;
        }

        public virtual void ClearKey()
        {
            if (_key == null)
                return;

            Array.Clear(_key.ToArray(), 0, _key.Length);
            ClearBuffer();
        }

        public virtual void ClearSalt()
        {
            if (_salt == null)
                return;

            Array.Clear(_salt, 0, _salt.Length);
        }

        private uint LE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private ulong LE_To_UInt64(byte[] bs, int off)
        {
            var lo = LE_To_UInt32(bs, off);
            var hi = LE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        private byte[] UInt64_To_LE(ulong n)
        {
            var bs = new byte[8];
            UInt64_To_LE(n, bs, 0);
            return bs;
        }

        private void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private void UInt64_To_LE(ulong n, byte[] bs, int off)
        {
            UInt32_To_LE((uint)(n), bs, off);
            UInt32_To_LE((uint)(n >> 32), bs, off + 4);
        }

        private void ClearBuffer()
        {
            Array.Clear(_bufferPin.ToArray(), 0, _bufferPin.Length);
        }

        public void Dispose()
        {
            try
            {
                Reset();
            }
            finally
            {
                ClearSalt();
                _bufferPin?.Dispose();
                _simdTempBuffer?.Dispose();
                _key?.Dispose();
            }
        }
    }
}
