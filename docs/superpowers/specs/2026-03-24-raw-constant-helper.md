# Phase 4: Raw Constant Helper Design Proposal

## Summary
To replace raw magic numbers with proper constants in `pkcs11_check.raw` while still maintaining strict transparency, `ctypes` compliance, and the ability to define vendor constants on-the-fly.

## Problem Statement
Currently, `pkcs11_check.raw` tests and types strictly use built-in Python `int`. This makes tests prone to magic-number passing where an attribute type could accidentally be passed as a mechanism type, and makes tracing/debugging opaque. However, we cannot lock the types down to standard `enum.IntEnum` structures because tests *must* be able to test undefined/vendor numbers.

## Proposed Strategy: `int` subclassing (`CK_CONSTANT`)

By explicitly inheriting from `int`, we retain native compatibility with `ctypes` (which seamlessly accepts subclassed ints for `c_ulong` fields) while allowing `mypy` to statically analyze types. 

A standard set of typing classes will define the PKCS#11 namespace securely:

```python
class CK_CONSTANT(int):
    """
    Base class for PKCS#11 integer constants. 
    Retains full `int` semantics for ctypes but allows strong type-hinting.
    """
    def __new__(cls, value: int, name: str | None = None):
        # Allow instantiation with just a number (vendor) or a named standard constant
        obj = super().__new__(cls, value)
        if name is not None:
            obj._name = name
        return obj

    @property
    def name(self) -> str:
        # Fall back to a hex representation if it's an unnamed vendor constant
        if hasattr(self, "_name"):
            return self._name
        return f"{self.__class__.__name__}(0x{self:08x})"

    def __repr__(self) -> str:
        return f"<{self.name}: {int(self)}>"

# Provide distinct types for the type checker
class CKA(CK_CONSTANT): pass
class CKM(CK_CONSTANT): pass
class CKK(CK_CONSTANT): pass
class CKR(CK_CONSTANT): pass

# Special handling for Flags so they can be securely combined while retaining their type
class CKF(CK_CONSTANT):
    """Flags that can be bitwise OR'd, returning the CKF type."""
    def __or__(self, other: int) -> "CKF":
        return CKF(super().__or__(other))
        
    def __and__(self, other: int) -> "CKF":
        return CKF(super().__and__(other))
        
    def __invert__(self) -> "CKF":
        return CKF(super().__invert__())
```

## Benefits and Use Cases

### 1. Type Enforcement
`mypy` will catch if you accidentally pass a `CKF` flag or random `int` instead of a `CKM` mechanism:
```python
def init_encryption(mechanism: CKM):
    pass
    
CKM_AES_CBC = CKM(0x00000122, "CKM_AES_CBC")
init_encryption(CKM_AES_CBC)  # mypy allows this
init_encryption(0x122)        # mypy prevents this
```

### 2. Arbitrary/Vendor Extensions
Because they wrap `int`, custom vendor constants can be constructed instantly directly inside a test file:
```python
VENDOR_ATTR = CKA(0x80001234)
# Mypy correctly identifies this as a valid CKA
# repr(VENDOR_ATTR) -> <CKA(0x80001234): 2147488308>
```

### 3. Bitwise Combinations (`CKF`)
The custom `CKF` subclass intercepts flags combined with `|`, `&`, or `~` and immediately returns a new `CKF` object. 
```python
CKF_RW_SESSION = CKF(0x00000002, "CKF_RW_SESSION")
CKF_SERIAL_SESSION = CKF(0x00000004, "CKF_SERIAL_SESSION")

flags = CKF_RW_SESSION | CKF_SERIAL_SESSION
# repr(flags) -> <CKF(0x00000006): 6>
```

### 4. Zero Ctypes Friction
Because `CK_CONSTANT` inherits strictly from `int`, `ctypes` handles parameters natively on all `RawPKCS11` methods:
```python
class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong)]

# ctypes converts it to an integer effortlessly without custom converters
attr = CK_ATTRIBUTE(type=CKA_CLASS)
```

## Next Steps
1. Insert these class models directly into `pkcs11_check/raw/types_std.py` (or a `constants.py` split).
2. Modify the standard constant generator script so it exports values wrapped in their respective classes instead of base ints (e.g. `CKM_RSA_PKCS = CKM(0x00000001, "CKM_RSA_PKCS")`).
3. Enforce the types heavily in `api.py` (i.e., `RawPKCS11`) and in recipes, converting tests progressively.
