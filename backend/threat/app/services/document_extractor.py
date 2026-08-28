"""文档内容抽取服务：支持 .txt / .md / .pdf / .docx。

用于前端「上传文档 → AI 自动解析」：仅抽取纯文本返回，
不调用 LLM，抽取结果直接填充到对应输入框，由用户决定后续是否建模。
"""

from __future__ import annotations

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 最大抽取字符数：防止超大文档导致前端/LLM 压力过大
MAX_EXTRACT_CHARS = 60000


class UnsupportedFileTypeError(ValueError):
    """不支持的文件类型。"""


def extract_text(filename: str, data: bytes) -> str:
    """根据文件扩展名抽取文本。

    Args:
        filename: 原始文件名（带扩展名）。
        data: 文件二进制内容。

    Returns:
        抽取出的纯文本（已做裁剪与清理）。

    Raises:
        UnsupportedFileTypeError: 扩展名不受支持。
    """
    ext = _extension(filename)
    try:
        if ext in (".txt", ".md", ".markdown", ".text"):
            text = _extract_plain(data)
        elif ext == ".pdf":
            text = _extract_pdf(data)
        elif ext == ".docx":
            text = _extract_docx(data)
        else:
            raise UnsupportedFileTypeError(
                f"不支持的文件类型「{ext or '(无扩展名)'}」，仅支持 .txt / .md / .pdf / .docx"
            )
    except UnsupportedFileTypeError:
        raise
    except Exception as e:  # noqa: BLE001 —— 解析失败统一转成用户可读错误
        logger.warning("文档解析失败 %s: %s", filename, e)
        raise ValueError(f"文档解析失败（{ext}），请检查文件是否损坏或格式是否规范") from e

    return _clean(text)


def extract_assets(filename: str, data: bytes) -> dict:
    """抽取文档的文本 + 内嵌图片（data URI 列表）。

    Args:
        filename: 原始文件名（带扩展名）。
        data: 文件二进制内容。

    Returns:
        {"text": str, "images": [data_uri, ...]}。images 仅对含内嵌图片的
        PDF / DOCX 返回；纯文本文件 images 为空列表。
    """
    ext = _extension(filename)
    images: list[str] = []
    text = ""
    try:
        if ext in (".txt", ".md", ".markdown", ".text"):
            text = _extract_plain(data)
        elif ext == ".pdf":
            text, images = _extract_pdf_assets(data)
        elif ext == ".docx":
            text, images = _extract_docx_assets(data)
        else:
            raise UnsupportedFileTypeError(
                f"不支持的文件类型「{ext or '(无扩展名)'}」，仅支持 .txt / .md / .pdf / .docx"
            )
    except UnsupportedFileTypeError:
        raise
    except Exception as e:  # noqa: BLE001
        logger.warning("文档解析失败 %s: %s", filename, e)
        raise ValueError(f"文档解析失败（{ext}），请检查文件是否损坏或格式是否规范") from e

    return {
        "text": _clean(text),
        "images": images[:12],  # 上限 12 张
    }


def _extension(filename: str) -> str:
    name = (filename or "").strip().lower()
    if "." not in name:
        return ""
    return name[name.rfind("."):]


def _extract_plain(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    # 兜底
    return data.decode("utf-8", errors="ignore")


def _extract_pdf(data: bytes) -> str:
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("服务器未安装 pypdf，无法解析 PDF") from e

    reader = PdfReader(io.BytesIO(data))
    parts: list[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001 —— 单页失败不影响整体
            continue
    return "\n".join(parts)


def _extract_docx(data: bytes) -> str:
    try:
        from docx import Document  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("服务器未安装 python-docx，无法解析 Word 文档") from e

    doc = Document(io.BytesIO(data))
    lines: list[str] = []
    for para in doc.paragraphs:
        t = para.text.strip()
        if t:
            lines.append(t)
    # 表格内容一并抽取
    for table in doc.tables:
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells]
            lines.append(" | ".join(c for c in cells if c))
    return "\n".join(lines)


def _extract_pdf_assets(data: bytes) -> tuple[str, list[str]]:
    """抽取 PDF 文本与内嵌图片（data URI 列表）。"""
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("服务器未安装 pypdf，无法解析 PDF") from e

    reader = PdfReader(io.BytesIO(data))
    parts: list[str] = []
    images: list[str] = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001
            continue
        try:
            for img in getattr(page, "images", []) or []:
                try:
                    uri = _image_to_data_uri(img.data, img.name)
                    if uri:
                        images.append(uri)
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(parts), images


def _extract_docx_assets(data: bytes) -> tuple[str, list[str]]:
    """抽取 DOCX 文本与内嵌图片（data URI 列表）。"""
    import zipfile

    parts: list[str] = []
    images: list[str] = []

    # 先抽取文本（保持与 extract_text 一致）
    try:
        from docx import Document  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("服务器未安装 python-docx，无法解析 Word 文档") from e

    try:
        doc = Document(io.BytesIO(data))
        for para in doc.paragraphs:
            t = para.text.strip()
            if t:
                parts.append(t)
        for table in doc.tables:
            for row in table.rows:
                cells = [c.text.strip() for c in row.cells]
                parts.append(" | ".join(c for c in cells if c))
    except Exception as e:  # noqa: BLE001
        logger.warning("DOCX 文本抽取失败，仅尝试提取图片: %s", e)

    # 抽取内嵌图片（word/media/*）
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                low = name.lower()
                if not low.startswith("word/media/") or not _looks_image(low):
                    continue
                try:
                    raw = zf.read(name)
                    uri = _image_to_data_uri(raw, name)
                    if uri:
                        images.append(uri)
                except Exception:  # noqa: BLE001
                    continue
    except Exception as e:  # noqa: BLE001
        logger.warning("DOCX 图片抽取失败: %s", e)

    return "\n".join(parts), images


def _looks_image(name: str) -> bool:
    return name.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"))


# 图片转 data URI 前的压缩参数：防止超大 base64 拖垮前端/LLM
_IMAGE_MAX_DIM = 1200        # 最长边像素上限
_IMAGE_JPEG_QUALITY = 75     # JPEG 压缩质量
# 每张图片 data URI 的字节数上限；超过则进一步降采样
_IMAGE_MAX_BYTES = 2_200_000  # ~2.2MB（含 base64 膨胀，原始字节约 1.6MB）


def _normalize_image(raw: bytes) -> bytes:
    """对图片做降采样 / 压缩，返回可安全内嵌的字节。

    优先使用 Pillow 高质量压缩；未安装时若图片超过上限则直接丢弃
    （由调用方忽略），避免超大图拖垮前端。不能识别 / 处理失败时
    返回原字节（交由上层判断是否超限）。
    """
    if not raw:
        return raw
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        # 无 Pillow：若原始字节已超上限，返回空以丢弃；否则原样返回
        return b"" if len(raw) > _IMAGE_MAX_BYTES else raw

    try:
        with Image.open(io.BytesIO(raw)) as img:
            img.load()
            # 统一转 RGB，避免透明 PNG 压缩成 JPEG 后出现黑底
            rgb = img.convert("RGB") if img.mode in ("RGBA", "P", "LA") else img
            if max(rgb.size) > _IMAGE_MAX_DIM:
                rgb.thumbnail((_IMAGE_MAX_DIM, _IMAGE_MAX_DIM), Image.LANCZOS)
            buf = io.BytesIO()
            # 依据预估体积决定是否转 JPEG：原始就是小 PNG 则保留 PNG
            if len(raw) <= _IMAGE_MAX_BYTES and rgb.format == "PNG":
                rgb.save(buf, format="PNG", optimize=True)
            else:
                rgb.save(buf, format="JPEG", quality=_IMAGE_JPEG_QUALITY, optimize=True)
            out = buf.getvalue()
            return out if len(out) <= _IMAGE_MAX_BYTES else b""
    except Exception:  # noqa: BLE001 —— 解码失败则走原始字节判定
        return raw


def _image_to_data_uri(raw: bytes, name: str) -> Optional[str]:
    """把图片字节转成 data URI（内嵌前先降采样压缩）。不能识别类型时返回 None。"""
    import base64
    import mimetypes

    if not raw:
        return None
    mime, _ = mimetypes.guess_type(name)
    if not mime or not mime.startswith("image/"):
        # 由扩展名推断
        ext = _extension(name)
        mime = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".webp": "image/webp",
        }.get(ext)
        if not mime:
            return None
    raw = _normalize_image(raw)
    if not raw:
        return None
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:{mime};base64,{b64}"


def _clean(text: str) -> str:
    """裁剪并清理抽取文本。"""
    if not text:
        return ""
    # 合并 3 个以上连续换行为两个换行（压缩多余空行）
    text = _collapse_blank_lines(text)
    # 限制长度
    if len(text) > MAX_EXTRACT_CHARS:
        text = text[:MAX_EXTRACT_CHARS] + "\n\n[内容过长，已截断…]"
    return text


def _collapse_blank_lines(text: str) -> str:
    import re

    return re.sub(r"\n{3,}", "\n\n", text)


def allowed_extensions() -> list[str]:
    return [".txt", ".md", ".markdown", ".text", ".pdf", ".docx"]
