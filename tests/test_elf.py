"""elf_tool 및 batch_tool 테스트.

gcc 로 보호기법이 다른 ELF 바이너리를 즉석에서 만들어 checksec 판정과
배치 멱등성을 검증한다. gcc 가 없는 환경에서는 스킵한다.
"""

import os
import shutil
import subprocess

import pytest

from tools.elf_tool import analyze_elf
from tools.batch_tool import scan_directory

_SAFE_C = (
    "#include <stdio.h>\n"
    "int main(){char b[64];fgets(b,sizeof(b),stdin);return 0;}"
)
_VULN_C = (
    "#include <string.h>\n"
    "void f(char*s){char b[64];strcpy(b,s);}\n"
    "int main(int c,char**v){if(c>1)f(v[1]);return 0;}"
)


def _compile(src: str, flags: list, out: str) -> bool:
    """C 소스를 주어진 플래그로 컴파일한다. 성공하면 True."""
    src_path = out + ".c"
    with open(src_path, "w") as f:
        f.write(src)
    proc = subprocess.run(
        ["gcc", *flags, src_path, "-o", out],
        capture_output=True,
    )
    return proc.returncode == 0 and os.path.isfile(out)


@pytest.fixture
def elf_dir(tmp_path):
    """보호기법이 다른 ELF 두 개를 담은 임시 디렉터리."""
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")

    d = str(tmp_path)
    full = os.path.join(d, "safe_full")
    off = os.path.join(d, "vuln_off")

    ok1 = _compile(
        _SAFE_C,
        ["-fstack-protector-all", "-pie", "-fPIE", "-Wl,-z,relro,-z,now"],
        full,
    )
    ok2 = _compile(
        _VULN_C,
        ["-fno-stack-protector", "-z", "execstack", "-no-pie"],
        off,
    )
    if not (ok1 and ok2):
        pytest.skip("gcc could not build test binaries with required flags")
    return d, full, off


def test_analyze_elf_full_protection(elf_dir):
    """모든 보호기법 켜진 바이너리는 High 난이도로 나온다."""
    _, full, _ = elf_dir
    result = analyze_elf(full)

    assert result["ok"] is True
    p = result["protections"]
    assert p["nx"] is True
    assert p["pie"] is True
    assert p["canary"] is True
    assert p["relro"] == "FULL"
    assert result["mitigation_analysis"]["difficulty"] == "High"


def test_analyze_elf_no_protection(elf_dir):
    """보호기법 꺼진 바이너리는 NX/Canary 가 꺼진 것으로 잡힌다."""
    _, _, off = elf_dir
    result = analyze_elf(off)

    p = result["protections"]
    assert p["nx"] is False
    assert p["canary"] is False


def test_analyze_elf_not_elf(tmp_path):
    """ELF 가 아닌 파일은 NOT_ELF 에러."""
    txt = tmp_path / "note.txt"
    txt.write_text("hello")
    result = analyze_elf(str(txt))

    assert result["ok"] is False
    assert result["error"]["code"] == "NOT_ELF"


def test_scan_directory_idempotent(elf_dir, tmp_path):
    """같은 디렉터리를 두 번 스캔해도 결과 행 수가 동일하다(멱등)."""
    d, _, _ = elf_dir
    out = str(tmp_path / "results.jsonl")

    r1 = scan_directory(d, out)
    rows1 = r1["metrics"]["total_rows"]

    r2 = scan_directory(d, out)
    rows2 = r2["metrics"]["total_rows"]

    assert rows1 == rows2
    # 파일 내용도 동일해야 한다.
    with open(out) as f:
        lines = [l for l in f if l.strip()]
    assert len(lines) == rows2
