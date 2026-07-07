"""Enable ``python -m pkcs11_check`` (and ``wine python -m pkcs11_check``).

Equivalent to the ``pkcs11-check`` console script; used where that shim is not on
PATH, notably the Windows/Wine validation target.
"""

from pkcs11_check.cli.app import main

if __name__ == "__main__":
    main()
