"""HTML -> PDF 导出（可选）。默认降级为写出 HTML 并提示。"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def html_to_pdf(html: str, out_path: Path) -> Path:
    """优先使用 weasyprint；未安装则回退保存 HTML。"""
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(out_path))
        return out_path
    except Exception as e:  # noqa: BLE001
        logger.warning("PDF 导出不可用（%s），回退为 HTML。", e)
        fallback = out_path.with_suffix(".html")
        fallback.write_text(html, encoding="utf-8")
        return fallback
