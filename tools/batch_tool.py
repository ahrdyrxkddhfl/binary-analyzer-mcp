"""여러 ELF 바이너리를 한 번에 스캔하는 배치 툴.

디렉터리 하나를 받아 그 안의 ELF 파일을 모두 analyze_elf 로 분석하고,
결과를 JSONL 로 적재한다. 같은 입력으로 다시 돌리거나 중간에 죽고
재시작해도 결과가 같도록(멱등) 파일의 정규화된 절대경로를 키로 upsert
한다. 처리 건수·스킵 건수를 로그로 남긴다.

DE 관점 포인트:
- 멱등성: realpath(절대·심볼릭 정리 경로)가 기본키라, b / ./b /
  /abs/b 로 같은 파일을 가리켜도 행이 한 개다. 이번 스캔에서 사라진
  파일의 오래된 행(stale row)은 제거한다.
- 원자적 쓰기: 임시 파일에 다 쓴 뒤 os.replace 로 교체해, 쓰는 도중
  죽어도 기존 결과가 통째로 날아가지 않는다.
- 안전: 출력 경로가 기존 파일이면서 우리 JSONL 형식이 아니면 덮어쓰지
  않고 거부한다(임의 파일 파괴 방지).
- 관측: 입력 대비 처리/스킵/에러 건수를 로그로 남긴다.
"""

import glob
import json
import os
import tempfile

from common import make_error, get_logger
from tools.elf_tool import analyze_elf

logger = get_logger(__name__)

# 우리 JSONL 임을 식별하는 마커. 모든 행이 dict 이고 "path" 키를 가진다.
# 기존 파일이 이 형식이 아니면 사용자가 지정한 다른 파일일 수 있으므로
# 덮어쓰지 않는다.


def _looks_like_our_jsonl(path: str) -> bool:
    """기존 파일이 우리가 만든 JSONL 형식인지 확인한다.

    첫 비어있지 않은 줄이 "path" 키를 가진 JSON 객체면 우리 형식으로
    본다. 빈 파일은 새로 써도 안전하므로 True.

    Args:
        path: 검사할 파일 경로.

    Returns:
        우리 형식이거나 빈 파일이면 True.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                return isinstance(obj, dict) and "path" in obj
        return True  # 내용 없음 → 덮어써도 안전.
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return False


def _load_existing(output_path: str) -> dict:
    """이미 적재된 JSONL 을 읽어 {정규화경로: 레코드} 로 만든다.

    Args:
        output_path: 기존 결과 JSONL 경로.

    Returns:
        정규화 경로를 키로 한 레코드 딕셔너리. 파일이 없으면 빈 dict.
    """
    records = {}
    if not os.path.isfile(output_path):
        return records
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records[rec["path"]] = rec
            except (json.JSONDecodeError, KeyError):
                logger.warning("skip malformed line in %s", output_path)
    return records


def _atomic_write(output_path: str, records: dict) -> None:
    """records 를 JSONL 로 원자적으로 기록한다.

    같은 디렉터리에 임시 파일로 먼저 쓴 뒤 os.replace 로 교체한다.
    os.replace 는 같은 파일시스템에서 원자적이라, 쓰는 도중 죽어도
    기존 output_path 는 온전히 남는다.

    Args:
        output_path: 최종 결과 경로.
        records: 정규화 경로를 키로 한 레코드 딕셔너리.
    """
    out_dir = os.path.dirname(os.path.abspath(output_path))
    fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for key in sorted(records):
                f.write(json.dumps(records[key], ensure_ascii=False) + "\n")
        os.replace(tmp, output_path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def scan_directory(
    directory: str,
    output_path: str = "scan_results.jsonl",
    pattern: str = "*",
) -> dict:
    """디렉터리 안의 ELF 파일을 모두 분석해 JSONL 로 적재한다.

    Args:
        directory: 스캔할 디렉터리 경로.
        output_path: 결과를 쓸 JSONL 파일 경로. 기존 파일이 우리 JSONL
            형식이 아니면 덮어쓰지 않고 거부한다.
        pattern: 파일 이름 glob 패턴(기본 "*", 모든 파일).

    Returns:
        입력/처리/스킵/에러 건수를 담은 요약 딕셔너리. 디렉터리가
        없거나 출력 경로가 안전하지 않으면 표준 에러 객체.
    """
    if not directory or not os.path.isdir(directory):
        return make_error(
            code="DIR_NOT_FOUND",
            message=f"directory not found: {directory}",
            hint="Provide an existing directory path",
        )

    # 출력 경로 안전 검사 — 기존 파일이 우리 형식이 아니면 거부.
    if os.path.isfile(output_path) and not _looks_like_our_jsonl(output_path):
        return make_error(
            code="UNSAFE_OUTPUT",
            message=f"refusing to overwrite non-JSONL file: {output_path}",
            hint="Choose a new output path or an existing scan JSONL",
        )

    records = _load_existing(output_path)

    candidates = sorted(glob.glob(os.path.join(directory, pattern)))
    n_input = 0
    n_scanned = 0
    n_skipped = 0
    n_error = 0

    # 이번 스캔에서 실제로 본 키. 여기 없는 기존 행은 stale 로 제거한다.
    seen_keys = set()

    for path in candidates:
        if not os.path.isfile(path):
            continue
        n_input += 1

        result = analyze_elf(path)

        if not result.get("ok"):
            code = result["error"]["code"]
            if code in ("NOT_ELF", "FILE_NOT_FOUND"):
                n_skipped += 1
            else:
                n_error += 1
            continue

        # 정규화된 절대경로를 기본키로 쓴다 — b / ./b / /abs/b 가 모두
        # 같은 키가 되어 멱등성이 유지된다.
        key = os.path.realpath(path)
        records[key] = {"path": key, **result}
        seen_keys.add(key)
        n_scanned += 1

    # 이번 디렉터리 스캔 대상 중 사라진 파일의 오래된 행 제거. 단
    # 다른 디렉터리에서 적재한 행은 건드리지 않도록, 이번에 스캔한
    # 디렉터리 아래 경로만 정리 대상으로 본다.
    scan_root = os.path.realpath(directory)
    for key in list(records):
        if key.startswith(scan_root + os.sep) and key not in seen_keys:
            del records[key]

    _atomic_write(output_path, records)

    logger.info(
        "scan_directory: input=%d scanned=%d skipped=%d error=%d total_rows=%d",
        n_input,
        n_scanned,
        n_skipped,
        n_error,
        len(records),
    )

    return {
        "ok": True,
        "directory": directory,
        "output_path": output_path,
        "metrics": {
            "input_files": n_input,
            "scanned": n_scanned,
            "skipped_non_elf": n_skipped,
            "errors": n_error,
            "total_rows": len(records),
        },
    }
