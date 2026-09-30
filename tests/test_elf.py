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


def _is_elf(path: str) -> bool:
    """산출물이 실제 ELF 인지 매직넘버로 확인한다.

    macOS 에서는 gcc 가 clang 별칭이라 존재하더라도 Mach-O 를 만들어
    ELF 테스트가 의미 없다. 이 검사로 ELF 가 아니면 fixture 가 skip 된다.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _compile(src: str, flags: list, out: str) -> bool:
    """C 소스를 주어진 플래그로 컴파일한다. ELF 산출 시에만 True."""
    src_path = out + ".c"
    with open(src_path, "w") as f:
        f.write(src)
    proc = subprocess.run(
        ["gcc", *flags, src_path, "-o", out],
        capture_output=True,
    )
    return proc.returncode == 0 and os.path.isfile(out) and _is_elf(out)


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


def test_scan_directory_idempotent_path_variants(elf_dir, tmp_path):
    """같은 디렉터리를 경로 표기만 바꿔 스캔해도 행 수가 늘지 않는다."""
    d, _, _ = elf_dir
    out = str(tmp_path / "results.jsonl")

    r1 = scan_directory(d, out)
    r2 = scan_directory(d + "/", out)          # 끝 슬래시
    r3 = scan_directory(os.path.join(d, "."), out)  # ./

    assert r1["metrics"]["total_rows"] == r2["metrics"]["total_rows"]
    assert r2["metrics"]["total_rows"] == r3["metrics"]["total_rows"]


def test_scan_directory_content_stable(elf_dir, tmp_path):
    """두 번 스캔 시 파일 내용(줄 집합)까지 동일해야 한다."""
    d, _, _ = elf_dir
    out = str(tmp_path / "results.jsonl")

    scan_directory(d, out)
    with open(out) as f:
        first = sorted(f.readlines())

    scan_directory(d, out)
    with open(out) as f:
        second = sorted(f.readlines())

    assert first == second


def test_scan_directory_refuses_non_jsonl(elf_dir, tmp_path):
    """기존 파일이 우리 JSONL 형식이 아니면 덮어쓰지 않는다."""
    d, _, _ = elf_dir
    victim = tmp_path / "important.txt"
    victim.write_text("do not delete me\n")

    result = scan_directory(d, str(victim))

    assert result["ok"] is False
    assert result["error"]["code"] == "UNSAFE_OUTPUT"
    # 원본 보존 확인.
    assert victim.read_text() == "do not delete me\n"


def test_analyze_elf_no_protection_relro_consistent(elf_dir):
    """protections.relro 와 mitigation 의 relro 판단이 일치해야 한다."""
    _, _, off = elf_dir
    result = analyze_elf(off)

    relro_field = result["protections"]["relro"]  # "NONE"/"PARTIAL"/"FULL"
    enabled = result["mitigation_analysis"]["enabled_protections"]
    relro_in_mit = [x for x in enabled if "relro" in x]

    if relro_field == "NONE":
        assert relro_in_mit == []
    elif relro_field == "PARTIAL":
        assert relro_in_mit == ["relro:partial"]
    else:
        assert relro_in_mit == ["relro:full"]


@pytest.fixture
def nested_dir(tmp_path):
    """하위 디렉터리와 .so 를 포함한 트리."""
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    d = str(tmp_path)
    sub = os.path.join(d, "sub")
    os.makedirs(sub, exist_ok=True)
    ok = True
    ok &= _compile(_SAFE_C, [], os.path.join(d, "a1"))
    ok &= _compile(_SAFE_C, [], os.path.join(d, "a2"))
    ok &= _compile(_SAFE_C, [], os.path.join(sub, "inner"))
    # .so 하나.
    so_src = os.path.join(d, "lib.c")
    with open(so_src, "w") as f:
        f.write("int f(){return 0;}")
    so_ok = subprocess.run(
        ["gcc", "-shared", "-fPIC", so_src, "-o", os.path.join(d, "a3.so")],
        capture_output=True,
    ).returncode == 0 and _is_elf(os.path.join(d, "a3.so"))
    if not (ok and so_ok):
        pytest.skip("gcc could not build nested ELF test tree")
    return d


def test_scan_does_not_delete_other_scans(nested_dir, tmp_path):
    """다른 디렉터리/패턴으로 적재한 행을 stale 로 오삭제하지 않는다(회귀)."""
    d = nested_dir
    out = str(tmp_path / "results.jsonl")

    r_sub = scan_directory(os.path.join(d, "sub"), out)
    assert r_sub["metrics"]["total_rows"] == 1  # sub/inner

    r_all = scan_directory(d, out)
    # sub/inner(1) + a1,a2,a3.so(3) = 4. sub/inner 가 지워지면 안 된다.
    assert r_all["metrics"]["total_rows"] == 4

    r_so = scan_directory(d, out, "*.so")
    # *.so 스캔이 기존 4개를 지우면 안 된다. a3.so 는 이미 있으므로 4 유지.
    assert r_so["metrics"]["total_rows"] == 4


def test_scan_shared_object_not_pie(nested_dir, tmp_path):
    """.so 는 PIE 로 잡히지 않는다."""
    from tools.elf_tool import analyze_elf as ae
    so = os.path.join(nested_dir, "a3.so")
    result = ae(so)
    assert result["protections"]["pie"] is False


def test_scan_skips_object_files(nested_dir, tmp_path):
    """.o(ET_REL) 파일은 skip 되어 결과에 들어가지 않는다."""
    o_path = os.path.join(nested_dir, "obj.o")
    subprocess.run(
        ["gcc", "-c", os.path.join(nested_dir, "lib.c"), "-o", o_path],
        capture_output=True,
    )
    if not os.path.isfile(o_path):
        pytest.skip("could not build .o")
    out = str(tmp_path / "r.jsonl")
    result = scan_directory(nested_dir, out, "*.o")
    assert result["metrics"]["scanned"] == 0
    assert result["metrics"]["skipped_non_elf"] >= 1


def test_load_existing_survives_non_dict_line(tmp_path):
    """JSONL 에 dict 아닌 줄([1])이 있어도 크래시하지 않는다(회귀)."""
    from tools.batch_tool import _load_existing
    p = tmp_path / "mixed.jsonl"
    p.write_text('{"path":"/x"}\n[1]\n{"path":"/y"}\n')
    records = _load_existing(str(p))
    assert "/x" in records and "/y" in records


def test_scan_removes_deleted_file(nested_dir, tmp_path):
    """스캔 대상이던 파일이 삭제되면 그 행도 제거된다(stale 실동작)."""
    d = nested_dir
    out = str(tmp_path / "results.jsonl")

    r1 = scan_directory(d, out)
    before = r1["metrics"]["total_rows"]
    assert before >= 2

    # a1 을 지우고 다시 스캔하면 행이 하나 줄어야 한다.
    os.remove(os.path.join(d, "a1"))
    r2 = scan_directory(d, out)
    assert r2["metrics"]["total_rows"] == before - 1


def test_scan_dotfile_not_deleted_by_star(nested_dir, tmp_path):
    """'.*' 로 적재한 dotfile 행이 '*' 스캔에 지워지지 않는다."""
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    d = nested_dir
    hidden = os.path.join(d, ".hidden")
    if not _compile(_SAFE_C, [], hidden):
        pytest.skip("could not build hidden ELF")
    out = str(tmp_path / "r.jsonl")

    r_dot = scan_directory(d, out, ".*")
    dot_rows = r_dot["metrics"]["total_rows"]
    assert dot_rows >= 1  # .hidden

    r_star = scan_directory(d, out, "*")
    # '*' 는 dotfile 을 안 보므로 .hidden 행은 유지돼야 한다.
    with open(out) as f:
        keys = {__import__("json").loads(l)["path"] for l in f if l.strip()}
    assert any(k.endswith("/.hidden") for k in keys)


def test_object_file_error_code(nested_dir):
    """.o 파일은 UNSUPPORTED_ELF_TYPE 로 반환된다."""
    o_path = os.path.join(nested_dir, "obj.o")
    subprocess.run(
        ["gcc", "-c", os.path.join(nested_dir, "lib.c"), "-o", o_path],
        capture_output=True,
    )
    if not (os.path.isfile(o_path) and _is_elf(o_path)):
        pytest.skip("could not build .o ELF")
    result = analyze_elf(o_path)
    assert result["ok"] is False
    assert result["error"]["code"] == "UNSUPPORTED_ELF_TYPE"


def test_analyze_elf_norelro_is_none(tmp_path):
    """-Wl,-z,norelro 빌드는 RELRO NONE 으로, mitigation 도 relro 없음."""
    if not shutil.which("gcc"):
        pytest.skip("gcc not available")
    out = str(tmp_path / "norelro")
    if not _compile(_SAFE_C, ["-Wl,-z,norelro", "-no-pie"], out):
        pytest.skip("could not build norelro ELF")
    result = analyze_elf(out)
    assert result["protections"]["relro"] == "NONE"
    enabled = result["mitigation_analysis"]["enabled_protections"]
    assert [x for x in enabled if "relro" in x] == []


def test_executable_shared_object_not_pie():
    """libc.so.6 같은 실행 가능 .so 는 PIE 로 잡히지 않는다."""
    import glob as _glob
    libcs = _glob.glob("/lib/**/libc.so.6", recursive=True) + \
        _glob.glob("/usr/lib/**/libc.so.6", recursive=True)
    libcs = [p for p in libcs if os.path.isfile(p)]
    if not libcs:
        pytest.skip("libc.so.6 not found")
    result = analyze_elf(libcs[0])
    assert result["ok"] is True
    assert result["protections"]["pie"] is False


def test_scan_survives_non_utf8_filename(nested_dir, tmp_path):
    """비-UTF8 파일명이 있어도 배치 전체가 죽지 않는다(회귀)."""
    d = nested_dir
    # 정상 ELF 를 비-UTF8 이름으로 복사.
    good = os.path.join(d, "a2")
    if not os.path.isfile(good):
        pytest.skip("no ELF to copy")
    bad = os.path.join(d.encode(), b"bad\xffname")
    with open(good, "rb") as src, open(bad, "wb") as dst:
        dst.write(src.read())

    out = str(tmp_path / "r.jsonl")
    result = scan_directory(d, out)  # 죽지 않아야 한다
    assert result["ok"] is True
    # 결과 파일이 정상적으로 읽혀야 한다(surrogate 없이 기록).
    import json
    with open(out) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    assert len(rows) >= 1
