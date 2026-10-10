# Test fixtures

- `inputs/` — copied from [msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool)'s `tests/inputs` (MIT).
- `expected/` — msoffcrypto-tool 6.0.0's decrypt output for each encrypted file in `inputs/` (same file name), produced with `msoffcrypto.OfficeFile(f).load_key(password=...)` + `decrypt(out)`. The tests check that this port's output matches byte for byte.

Passwords: `xor_password_123456789012345.xls` uses `123456789012345`; every other encrypted file uses `Password1234_`.
