#include "concrete-ffi.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>

#define NO_ERR(s)                                                              \
  s;                                                                           \
  assert(ERR == 0);

const int PRECISION = 3;
const int SHIFT = 64 - (PRECISION + 1);

int main(void) {
  int ERR = 0;

  // We generate the random sources
  SecretRandomGenerator *secret_gen =
      NO_ERR(allocate_secret_generator(&ERR, 0, 0));
  EncryptionRandomGenerator *enc_gen =
      NO_ERR(allocate_encryption_generator(&ERR, 0, 0));
  Variance variance = {0.0000000000000000};

  LweSize lwe_size = {599};

  // We generate the secret keys
  LweSecretKey_u64 *lwe_sk =
      NO_ERR(allocate_lwe_secret_key_u64(&ERR, lwe_size));
  NO_ERR(fill_lwe_secret_key_u64(&ERR, lwe_sk, secret_gen));

  // We generate the ciphertexts
  LweCiphertext_u64 *ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, lwe_size));

  Plaintext_u64 plaintext = {((uint64_t)4) << SHIFT};

  NO_ERR(encrypt_lwe_u64(&ERR, lwe_sk, ct, plaintext, enc_gen, variance));

  BufferView plaintext_view = serialize_lwe_ciphertext_u64(ct);

  size_t len = plaintext_view.length;

  uint8_t *serialized_ct = malloc(len);

  memcpy(serialized_ct, plaintext_view.pointer, len);

  BufferView serialized_ct_view;
  serialized_ct_view.pointer = serialized_ct;
  serialized_ct_view.length = len;

  LweCiphertext_u64 *ct2 = deserialize_lwe_ciphertext_u64(serialized_ct_view);

  Plaintext_u64 output_ks = {0};
  NO_ERR(decrypt_lwe_u64(&ERR, lwe_sk, ct2, &output_ks));
  double obtained_double_ks = (double)output_ks._0 / pow(2, SHIFT);

  printf("Intermidiate Expected: 4, Obtained: %f\n", obtained_double_ks);
}