# Roadmap

A non-binding view of where pkcs11-check is heading, so users can see what is
planned or under consideration. Nothing here is a dated commitment; current
behavior is documented in the README and the rest of `docs/`.

## Planned / under consideration

- *Rate-limit-aware retry and backoff.* Some providers - notably cloud KMS
  bridges and network HSMs - throttle a client by returning an error (a busy,
  throttle, or device-error return code) instead of blocking. pkcs11-check
  should recognize such throttle responses and apply a bounded
  backoff-and-retry at the operation layer (much like the existing
  provider-restart recovery), so transient rate limiting does not surface as
  spurious findings. This will be opt-in / configurable, so strict runs can
  still treat every return code at face value.

- *SO (security officer) login flows.* CKU_SO workflows, including
  trusted-certificate import with `CKA_TRUSTED=True`, are not yet covered.

- *Wider interop simulators.* Provider-generated in-band IV profiles,
  proxy/loader mutable-parameter preservation checks, and broader
  mutable-output simulator targets.

- *Fuzzing / external fuzzer hooks.* Exposing the input-boundary probes to
  external fuzzers is under consideration.
