"""ACVP AES test suite (split into submodules).

Intentionally empty: importing this package must have no side effects. Modules
import the helpers they need directly from ``base`` / ``base_loader`` / the
``base_runner_*`` submodules. (A previous convenience re-export here eagerly
imported ``base_loader``, which carried a module-level skip -- that fired during
conftest loading and crashed collection when ACVP vectors were absent. See
``acvp_loader.require_acvp_vectors`` and ``tests/test_acvp_collection_no_data.py``.)
"""
