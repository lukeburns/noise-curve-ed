/* eslint-disable camelcase */
const red25519 = require('red25519')
const assert = require('nanoassert')

const DHLEN = 32
const PKLEN = 32 // ed25519 public keys are 32 bytes
const SCALARLEN = 32
const SKLEN = 64 // red25519 secretKey is 64 bytes (32-byte private + 32-byte public)
const ALG = 'Red25519'

module.exports = {
  DHLEN,
  PKLEN,
  SCALARLEN,
  SKLEN,
  ALG,
  name: ALG,
  generateKeyPair,
  generateSeedKeyPair,
  dh
}

function generateKeyPair (seed) {
  if (seed) return red25519.keyPair(seed.subarray(0, 32))
  return red25519.keyPair()
}

function generateSeedKeyPair (seed) {
  assert(seed.byteLength === SCALARLEN, 'seed must be 32 bytes')
  return generateKeyPair(seed)
}

function dh (publicKey, { scalar, secretKey }) {
  assert(publicKey.byteLength === PKLEN, `publicKey must be ${PKLEN} bytes`)

  if (scalar) {
    assert(scalar.byteLength === SCALARLEN, 'scalar must be 32 bytes')
    const localKeyPair = red25519.deriveKeyPair(scalar)
    return red25519.deriveSharedSecret(localKeyPair.secretKey, publicKey)
  }

  assert(secretKey.byteLength === SKLEN, 'secretKey must be 64 bytes')

  return red25519.deriveSharedSecret(secretKey, publicKey)
}
