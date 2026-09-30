"""여러 ELF 바이너리를 한 번에 스캔하는 배치 툴.

디렉터리 하나를 받아 그 안의 ELF 파일을 모두 analyze_elf 로 분석하고,
결과를 JSONL 로 적재한다. 같은 입력으로 다시 돌리거나 중간에 죽고
재시작해도 결과가 같도록(멱등) 파일 경로를 키로 upsert 한다. 처리
건수·스킵 건수를 로그로 남긴다.

DE 관점 포인트:
- 멱등성: 파일 경로가 기본키. 재실행 시 중복 행을 만들지 않는다.
- 관측: 입력 대비 처리/스킵/에러 건수를 로그로 남긴다.
- 원본 보존: 분석 결과(정제 데이터)만 JSONL 로 쌓고, 입력 바이너리는
  건드리지 않는다.
"""

import glob
import json
import os

from common import make_error, get_logger
from tools.elf_tool import analyze_elf

logger = get_logger(__name__)


def _load_existing(output_path: str) -> dict:
    """이미 적재된 JSONL 을 읽어 {파일경로: 레코드} 로 만든다.

    재실행 시 기존 결과를 키로 들고 있다가 덮어쓰기(upsert) 하기 위함.
    깨진 줄은 건너뛰어 부분 손상에도 나머지를 살린다.

    Args:
        output_path: 기존 결과 JSONL 경로.

    Returns:
        파일 경로를 키로 한 레코드 딕셔너리. 파일이 없으면 빈 dict.
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


def scan_directory(
    directory: str,
    output_path: str = "scan_results.jsonl",
    pattern: str = "*",
) -> dict:
    """디렉터리 안의 ELF 파일을 모두 분석해 JSONL 로 적재한다.

    Args:
        directory: 스캔할 디렉터리 경로.
        output_path: 결과를 쓸 JSONL 파일 경로.
        pattern: 파일 이름 glob 패턴(기본 "*", 모든 파일).

    Returns:
        입력/처리/스킵/에러 건수를 담은 요약 딕셔너리. 디렉터리가
        없으면 표준 에러 객체.
    """
    if not directory or not os.path.isdir(directory):
        return make_error(
            code="DIR_NOT_FOUND",
            message=f"directory not found: {directory}",
            hint="Provide an existing directory path",
        )

    # 기존 결과를 키로 들고 시작 — upsert 로 멱등성 확보.
    records = _load_existing(output_path)

    candidates = sorted(glob.glob(os.path.join(directory, pattern)))
    n_input = 0      # ELF 후보(파일)
    n_scanned = 0    # 실제 분석 성공
    n_skipped = 0    # ELF 아님 등으로 건너뜀
    n_error = 0      # 분석 중 에러

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

        # 파일 경로를 기본키로 덮어쓴다 — 같은 파일을 다시 스캔해도
        # 행이 늘지 않는다.
        records[path] = {"path": path, **result}
        n_scanned += 1

    # JSONL 전체를 다시 쓴다. 키로 관리하므로 재실행 결과가 동일하다.
    with open(output_path, "w", encoding="utf-8") as f:
        for path in sorted(records):
            f.write(json.dumps(records[path], ensure_ascii=False) + "\n")

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
