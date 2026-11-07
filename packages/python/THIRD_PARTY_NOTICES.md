# Third-party notices

## Public Suffix List
`src/mnemowall/signals/data/public_suffix_list.dat.gz` is a gzip-compressed, otherwise unmodified copy
of the Public Suffix List
(https://publicsuffix.org), snapshot from github.com/publicsuffix/list at commit
`9dfbe81931367b3f0af21035c36ae7eeb830dd88`, licensed under the Mozilla Public License 2.0
(https://mozilla.org/MPL/2.0/). Its license header is preserved in the file.

## google-re2
Runtime dependency (not vendored). RE2 and its Python bindings are licensed under the BSD 3-Clause
License (https://github.com/google/re2).

## cryptography
Runtime dependency (not vendored), used for Ed25519 signatures, AES-256-GCM, HKDF and HMAC.
Dual-licensed under the Apache License 2.0 or the BSD 3-Clause License
(https://github.com/pyca/cryptography).

## keyring (optional)
Installed only with the `keychain` extra (`mnemowall[keychain]`). Licensed under the MIT License
(https://github.com/jaraco/keyring).

## langgraph, langgraph-checkpoint (optional)
Installed only with the `langgraph` extra (`mnemowall[langgraph]`). Licensed under the MIT License
(https://github.com/langchain-ai/langgraph).

## mem0ai (optional)
Installed only with the `mem0` extra (`mnemowall[mem0]`). Licensed under the Apache License 2.0
(https://github.com/mem0ai/mem0). It brings in `qdrant-client` (Apache-2.0), `openai`, `posthog`
and `sqlalchemy` as its own dependencies.

## PyYAML (optional)
Installed only with the `yaml` extra (`mnemowall[yaml]`); used through `yaml.safe_load` only.
Licensed under the MIT License (https://github.com/yaml/pyyaml).
