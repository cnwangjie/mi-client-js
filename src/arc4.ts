export const createArc4 = (key: Buffer) => {
  const state = Buffer.allocUnsafe(256)
  for (let i = 0; i < 256; i += 1) state[i] = i
  let i1 = 0
  let i2 = 0
  const keylen = key.length
  for (let i = 0; i < 256; i += 1) {
    i2 = (i2 + key[i1] + state[i]) % 256
    const t = state[i]
    state[i] = state[i2]
    state[i2] = t
    i1 = (i1 + 1) % keylen
  }

  let x = 0
  let y = 0

  // for (i=0; i<len; i++)
  // {
  //     x = (x + 1) % 256;
  //     y = (y + rc4State->state[x]) % 256;
  //     {
  //         unsigned t;      /* Exchange state[x] and state[y] */
  //         t = rc4State->state[x];
  //         rc4State->state[x] = rc4State->state[y];
  //         rc4State->state[y] = (uint8_t)t;
  //     }
  //     {
  //         unsigned xorIndex;   /* XOR the data with the stream data */
  //         xorIndex=(rc4State->state[x]+rc4State->state[y]) % 256;
  //         out[i] = in[i] ^ rc4State->state[xorIndex];
  //     }
  // }

  const encrypt = (input: Buffer, out: Buffer) => {
    const len = input.length
    for (let i = 0; i < len; i += 1) {
      x = (x + 1) % 256
      y = (y + state[x]) % 256
      {
        const t = state[x]
        state[x] = state[y]
        state[y] = t
      }
      {
        const index = (state[x] + state[y]) % 256
        out[i] = input[i] ^ state[index]
      }
    }
  }

  return {
    state,
    x,
    y,
    encrypt(buf: Buffer) {
      const result = Buffer.alloc(buf.length)
      encrypt(buf, result)
      return result
    },
  }
}
