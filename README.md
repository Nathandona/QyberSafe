# QyberSafe

**QyberSafe** is a modern, developer-friendly C++/Python library focused on easy, robust, and practical integration of post-quantum cryptography—the essential building block for quantum-ready cybersecurity. Designed for fintech, cloud, and enterprise environments, QyberSafe provides modular quantum-safe encryption, key exchange (Kyber, Dilithium, SPHINCS+), and transition tooling that helps future-proof your data and communications against quantum threats.

## Features

- Easy integration (C++, Python bindings)
- NIST-standard algorithms: Kyber, Dilithium, SPHINCS+
- Drop-in hybrid (classical + PQC) key exchange modules
- Crypto agility: swap algorithms with minimal code changes
- Performance-optimized for servers, embedded, and cloud
- Secure primitives, randomization, and attack mitigation
- Migration guidance and tooling

## Quick Start

```cpp
#include <qybersafe/qybersafe.h>

auto keypair = qybersafe::kyber::generate_keypair();
auto ciphertext = qybersafe::kyber::encrypt(public_key, message);
// Decrypt
auto plaintext = qybersafe::kyber::decrypt(private_key, ciphertext);
```

## Why Quantum-Safe?

Classical algorithms such as RSA and ECC are vulnerable to quantum attacks. QyberSafe leverages the latest lattice-based standards (NIST PQC finalists) to help organizations thwart “harvest now, decrypt later” attacks and comply with emerging regulations.

## Algorithms Supported

- Kyber (Key Encapsulation)
- Dilithium (Digital Signatures)
- SPHINCS+ (Hash-Based Signatures)
- Crypto-agile APIs for easy algorithm swaps

## Roadmap

- Extended language bindings (Go, Rust)
- Enhanced TLS/SSH hybrid modules
- Hardware acceleration support
- Seamless legacy migration scripts

## Documentation

Full API documentation, migration guides, and code samples are available in the [docs](./docs) directory.

## License

MIT License

## Contributing

- Fork this repo and make PRs for features or fixes
- Open issues for bugs, integration help, or feature requests

## Security Contact

Please report vulnerabilities securely to [security@qybersafe.io](mailto:security@qybersafe.io).