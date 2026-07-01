// GPU nonce search for OmegaCases mining:
//   SHA256(previous_hash_ascii(64B) + id_ascii(32B) + decimal(nonce))
//
// The 64-byte previous_hash block is pre-compressed on the CPU into
// `midstate`. Each work-item only builds block two (id tail + ascii nonce +
// padding) and runs one more SHA-256 compression round, then compares the
// digest against `target`.

__constant uint K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_block(const uint *h_in, const uint *blk, uint *out) {
    uint w[64];
    for (int i = 0; i < 16; i++) { w[i] = blk[i]; }
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr(w[i-15], 7u) ^ rotr(w[i-15], 18u) ^ (w[i-15] >> 3u);
        uint s1 = rotr(w[i-2], 17u) ^ rotr(w[i-2], 19u) ^ (w[i-2] >> 10u);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a = h_in[0], b = h_in[1], c = h_in[2], d = h_in[3];
    uint e = h_in[4], f = h_in[5], g = h_in[6], hh = h_in[7];
    for (int i = 0; i < 64; i++) {
        uint s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
        uint ch = (e & f) ^ (~e & g);
        uint temp1 = hh + s1 + ch + K[i] + w[i];
        uint s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = s0 + maj;
        hh = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    out[0] = h_in[0] + a; out[1] = h_in[1] + b; out[2] = h_in[2] + c; out[3] = h_in[3] + d;
    out[4] = h_in[4] + e; out[5] = h_in[5] + f; out[6] = h_in[6] + g; out[7] = h_in[7] + hh;
}

// output layout: [0]=found flag, [1]=nonce_hi, [2]=nonce_lo, [3..10]=hash words
__kernel void search(
    __global const uint *midstate,
    __global const uint *prefix_tail,
    __global const uint *target,
    const uint base_hi,
    const uint base_lo,
    __global volatile uint *output
) {
    if (output[0] != 0u) { return; }

    ulong base = (((ulong)base_hi) << 32) | (ulong)base_lo;
    ulong nonce = base + (ulong)get_global_id(0);

    // Fixed-trip-count digit extraction (some GPU compilers miscompile
    // data-dependent loop bounds over private arrays - keep every loop in
    // this kernel at a constant trip count to stay portable).
    uchar digits[20];
    int ndig = 1;
    bool done = false;
    ulong v = nonce;
    for (int k = 0; k < 20; k++) {
        if (!done) {
            digits[k] = (uchar)(v % 10);
            v /= 10;
            ndig = k + 1;
            if (v == 0) { done = true; }
        }
    }

    int msgLen = 32 + ndig;
    uint totalBits = (uint)((96 + ndig) * 8);

    uchar bytes[64];
    for (int i = 0; i < 64; i++) {
        uchar val = 0;
        if (i < 32) {
            uint w = prefix_tail[i / 4];
            uint shift = (3u - (uint)(i % 4)) * 8u;
            val = (uchar)((w >> shift) & 0xffu);
        } else if (i < msgLen) {
            int di = i - 32;
            val = (uchar)('0' + digits[ndig - 1 - di]);
        } else if (i == msgLen) {
            val = 0x80;
        } else if (i == 60) {
            val = (uchar)((totalBits >> 24) & 0xffu);
        } else if (i == 61) {
            val = (uchar)((totalBits >> 16) & 0xffu);
        } else if (i == 62) {
            val = (uchar)((totalBits >> 8) & 0xffu);
        } else if (i == 63) {
            val = (uchar)(totalBits & 0xffu);
        }
        bytes[i] = val;
    }

    uint blk[16];
    for (int i = 0; i < 16; i++) {
        blk[i] = ((uint)bytes[i*4] << 24) | ((uint)bytes[i*4+1] << 16) | ((uint)bytes[i*4+2] << 8) | (uint)bytes[i*4+3];
    }

    uint mstate[8];
    for (int i = 0; i < 8; i++) { mstate[i] = midstate[i]; }
    uint digest[8];
    sha256_block(mstate, blk, digest);

    bool less = false;
    bool eq = true;
    for (int i = 0; i < 8 && eq; i++) {
        if (digest[i] < target[i]) { less = true; eq = false; }
        else if (digest[i] > target[i]) { eq = false; }
    }

    if (less) {
        uint old = atomic_xchg(&output[0], 1u);
        if (old == 0u) {
            output[1] = (uint)(nonce >> 32);
            output[2] = (uint)(nonce & 0xffffffffu);
            for (int i = 0; i < 8; i++) { output[3 + i] = digest[i]; }
        }
    }
}
