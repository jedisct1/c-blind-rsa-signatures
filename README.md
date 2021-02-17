# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This implementation is compatible with OpenSSL and BoringSSL.

## Usage

```c
#include <blind_rsa.h>

const uint8_t msg[]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
const size_t  msg_len = sizeof msg;

// Blind a message

RSA_BLIND_MESSAGE blind_message;
assert(RSA_blind(&blind_message, rsa, msg, msg_len) == 1);

// Compute a signature for a blind message

RSA_BLIND_SIGNATURE blind_sig;
assert(RSA_blind_sign(&blind_sig, rsa, blind_message.blind_message,
                      blind_message.blind_message_len) == 1);

// Verify the signature

assert(RSA_blind_verify(&blind_sig, blind_message.secret,
                        blind_message.secret_len, rsa, msg, msg_len) == 1);

RSA_BLIND_MESSAGE_deinit(&blind_message);
RSA_BLIND_SIGNATURE_deinit(&blind_sig);
```

For consistency with the inconsistent OpenSSL API, functions return `1` on success and `0` on error.
