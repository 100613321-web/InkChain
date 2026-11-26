# InkChain

Encrypted diary for the terminal. Every entry is encrypted (AES-256-GCM), signed (ECDSA P-256)
and linked to the previous one by a SHA-256 hash chain, so editing, deleting, reordering or
replaying entries is detected. A signed "diary head" (entry count + last hash) also catches
deletion of the newest entries.

## Install and run (clean environment)

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Tests

```
python -m pytest -v
```

Tests use a cheap scrypt cost so they run fast. The test marked `prod_params` runs with the
real parameters (N=2^17, r=8, p=1): `python -m pytest -m prod_params`.

## Structure

```
crypto/    kdf.py (scrypt)  aead.py (AES-GCM)  signing.py (ECDSA)  chain.py (hash chain, head)
storage/   files.py         JSON files, atomic writes, 0600 permissions
services/  auth.py          register, login, lockout, key unlocking
           diary.py         create / read / verify entries
ui/        cli.py           console interface
tests/     pytest suite, positive and negative tests
```

Data is written to `data/` (ignored by git). Never commit it.

## Known limits

- Restoring an old copy of **all** data files at once (rollback) cannot be detected locally.
- Python cannot reliably wipe keys from memory; logout only drops the references.
