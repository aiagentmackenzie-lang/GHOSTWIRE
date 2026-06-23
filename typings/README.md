"""Minimal partial type stubs for the third-party surfaces GHOSTWIRE uses.

These exist so `mypy engine` is NOT blind at the dpkt / scapy / ja4plus boundary
(production-plan Phase 6.1). They model only the attributes we actually touch;
they are intentionally not complete stubs of the libraries.

Mypy discovers stubs in this `typings/` directory via the MYPYPATH set in
pyproject (`mypy_path`), so dropping the blanket `ignore_missing_imports`
surfaces real type errors at our code instead of hiding them.
"""