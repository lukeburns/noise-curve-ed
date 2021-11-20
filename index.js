/* eslint-disable camelcase */
const sodium = require('sodium-universal')
const assert = require('nanoassert')
const b4a = require('b4a')

const DHLEN = sodium.crypto_core_ristretto255_BYTES
const PKLEN = sodium.crypto_core_ristretto255_BYTES
const SKLEN = sodium.crypto_core_ristretto255_SCALARBYTES
const ALG = 'ristretto255'

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  ALG,
  name: ALG,
  generateKeyPair,
  dh
}

function generateKeyPair (sk) {
  if (!sk) {
    sk = b4a.alloc(SKLEN)
    sodium.crypto_core_ristretto255_scalar_random(sk)
  }
  const pk = b4a.alloc(PKLEN)
  sodium.crypto_scalarmult_ristretto255_base(pk, sk)
  return {
    publicKey: pk,
    secretKey: sk
  }
}

function dh (pk, lsk) {
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  const output = b4a.alloc(DHLEN)

  sodium.crypto_scalarmult_ristretto255(
    output,
    lsk,
    pk
  )

  return output
}
