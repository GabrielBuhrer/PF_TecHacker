import os
import pytest

# Teste de payloads exemplo — também fica desativado até você habilitar.
if os.getenv("ENABLE_STRICT_TESTS") != "1":
    pytest.skip("Defina ENABLE_STRICT_TESTS=1 para habilitar estes testes de payloads.", allow_module_level=True)

from utils import scanners as scanners_mod

def test_basic_payloads_collection_exists():
    # Garante que exista ao menos um conjunto de payloads/sinais no módulo
    has_payloads = any(name for name in dir(scanners_mod) if "payload" in name.lower())
    assert has_payloads, "Esperava encontrar coleções de payloads no módulo scanners."