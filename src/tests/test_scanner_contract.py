import os
import pytest

if os.getenv("ENABLE_STRICT_TESTS") != "1":
    pytest.skip("Defina ENABLE_STRICT_TESTS=1 para habilitar estes testes de contrato.", allow_module_level=True)

from utils import scanners as scanners_mod

def get_class(mod, name):
    return getattr(mod, name, None)

@pytest.mark.parametrize("class_name,sample_html,expect_keywords", [
    ("CSRFScanner", "<form method=\"post\"><input name=\"amount\"></form>", ["csrf", "token", "missing"]),
    ("DirectoryTraversalScanner", "root:x:0:0:root:/root:/bin/bash", ["traversal", "etc/passwd"]),
    ("FileInclusionScanner", "<?php include($_GET['file']); ?>", ["file inclusion", "lfi"]),
    ("InfoDisclosureScanner", "Index of /\n.env\nconfig.php", [".env", "index of"]),
    ("CommandInjectionScanner", "uid=1000(test) gid=1000(test) groups=1000(test)", ["command", "injection", "uid="]),
])
def test_scanner_detects_basic_patterns(class_name, sample_html, expect_keywords):
    Cls = get_class(scanners_mod, class_name)
    assert Cls is not None, f"{class_name} não encontrado em utils/scanners.py"

    scanner = Cls()

    candidate_methods = ["scan", "check", "detect", "run"]
    method = None
    for m in candidate_methods:
        if hasattr(scanner, m):
            method = getattr(scanner, m)
            break
    assert callable(method), "Nenhum método de varredura encontrado (scan/check/detect/run)."

    url = "https://example.com/test"
    found = None
    try:
        found = method(url, sample_html)
    except TypeError:
        try:
            found = method(sample_html)
        except TypeError:
            found = method(url=url, html=sample_html)

    assert found is not None, "O método deve retornar algum resultado (lista/dict/obj)."

    s = str(found).lower()
    matches = sum(1 for k in expect_keywords if k in s)
    assert matches >= 1, f"Esperado pelo menos 1 indicação entre {expect_keywords}, obtive: {s}"