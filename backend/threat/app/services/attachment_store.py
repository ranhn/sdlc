"""文档附件存储服务：把上传的文档原样保存到磁盘，供后续 AI 建模时按附件读取。

与 document_extractor 不同，本服务保留原始二进制文件（PDF/DOCX 中含架构图、
数据流图等），而不是只抽取纯文本。附件由 attachment_id 标识，后端可根据
attachment_id 读取原文件及其中内嵌的图片（以 base64 data URI 形式交给多模态 LLM）。
"""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
import re
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
ATTACH_DIR = DATA_DIR / "attachments"

# 单附件图片数量/大小上限，防止超大附件压垮 LLM 请求
MAX_IMAGES_PER_ATTACH = 12
MAX_IMAGE_BYTES = 4 * 1024 * 1024  # 单张图片原始字节上限 4MB

# attachment_id 白名单：仅允许 12 位十六进制（由 uuid.uuid4().hex[:12] 生成），
# 用于防御路径穿越（../ 越权读取/删除磁盘目录）。
_ATTACH_ID_RE = re.compile(r"^[0-9a-f]{12}$")


def _check_attach_id(attachment_id: str) -> None:
    """校验 attachment_id 是否符合白名单格式，不符合直接抛 ``ValueError``。"""
    if not _ATTACH_ID_RE.fullmatch(str(attachment_id or "")):
        raise ValueError(f"非法的附件 ID：{attachment_id!r}")


def _ensure_dirs() -> None:
    ATTACH_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(filename: str) -> str:
    """清理文件名，仅保留文件名（去掉路径部分）并替换危险字符。"""
    name = (filename or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff_.\-\s]", "_", name)
    return name.strip() or "document"


def save_attachment(
    filename: str,
    data: bytes,
    *,
    extracted_text: str,
    images: list[str],
) -> dict[str, Any]:
    """保存上传的文档为附件，并返回附件元数据。

    Args:
        filename: 原始文件名。
        data: 文件原始二进制。
        extracted_text: 已抽取的文本（用于降级 / 供前端参考）。
        images: 从文档中抽取的内嵌图片，data URI 列表。

    Returns:
        dict，包含 attachment_id / filename / filetype / chars / images / text。
    """
    _ensure_dirs()
    attachment_id = uuid.uuid4().hex[:12]
    folder = ATTACH_DIR / attachment_id
    folder.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_name(filename)
    filetype = Path(safe_name).suffix.lower()

    # 保存原始二进制文件
    file_path = folder / f"original{filetype if filetype else '.bin'}"
    file_path.write_bytes(data)

    # 保存抽取图片为独立文件（保留 data URI），便于后续读取
    image_paths: list[str] = []
    for i, uri in enumerate(images):
        if not uri or i >= MAX_IMAGES_PER_ATTACH:
            continue
        try:
            mime, b64 = _split_data_uri(uri)
            raw = base64.b64decode(b64)
            if len(raw) > MAX_IMAGE_BYTES:
                continue
            ext = mimetypes.guess_extension(mime.split(";")[0].strip()) or ".img"
            ip = folder / f"image_{i:03d}{ext}"
            ip.write_bytes(raw)
            image_paths.append(uri)
        except Exception as e:  # noqa: BLE001 —— 单张图失败不影响整体
            logger.warning("保存附件图片失败 %s: %s", filename, e)

    meta: dict[str, Any] = {
        "attachment_id": attachment_id,
        "filename": safe_name,
        "filetype": filetype,
        "chars": len(extracted_text),
        "images": image_paths,
        "text": extracted_text,
        "image_count": len(image_paths),
    }
    (folder / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("附件已保存 %s (%s, %d 字符, %d 张图)", attachment_id, safe_name, len(extracted_text), len(image_paths))
    return meta


def load_attachment(attachment_id: str) -> Optional[dict[str, Any]]:
    """根据 attachment_id 读取附件元数据；不存在时返回 None。"""
    _check_attach_id(attachment_id)
    folder = ATTACH_DIR / attachment_id
    meta_file = folder / "meta.json"
    if not folder.is_dir() or not meta_file.is_file():
        return None
    try:
        return json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        logger.warning("读取附件元数据失败 %s: %s", attachment_id, e)
        return None


def get_attachment_images(attachment_id: str) -> list[str]:
    """返回附件中的图片 data URI 列表；读取失败返回空列表。"""
    meta = load_attachment(attachment_id)
    if not meta:
        return []
    return list(meta.get("images", []) or [])


def delete_attachment(attachment_id: str) -> None:
    """删除附件目录。"""
    _check_attach_id(attachment_id)
    folder = ATTACH_DIR / attachment_id
    if folder.is_dir():
        for f in folder.glob("*"):
            try:
                f.unlink()
            except Exception:  # noqa: BLE001
                pass
        try:
            folder.rmdir()
        except Exception:  # noqa: BLE001
            pass


def _split_data_uri(data_uri: str) -> tuple[str, str]:
    """把 data URI 拆成 (mime, base64)。非 data URI 直接返回 (text/plain, uri)。"""
    if data_uri.startswith("data:"):
        try:
            header, _, b64 = data_uri.partition(",")
            mime = header[5:].split(";")[0]
            return mime or "application/octet-stream", b64
        except Exception:  # noqa: BLE001
            pass
    return "text/plain", data_uri
