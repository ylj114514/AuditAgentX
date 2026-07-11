"""RepoParserAgent —— 仓库解析智能体。

不依赖 LLM，直接调用 repository 模块提取项目元信息。
"""
from __future__ import annotations

from pathlib import Path

from backend.repository.language_detector import scan_files, detect_languages
from backend.repository.dependency_parser import parse_dependencies
from backend.repository.file_tree_builder import build_tree, find_entrypoints


class RepoParserAgent:
    name = "repo_parser_agent"

    def run(self, code_root: Path, *, max_files: int | None = None) -> dict:
        max_files = max_files or getattr(self, "_max_files", 20000)
        files = scan_files(code_root, max_files=max_files)
        languages, loc = detect_languages(files)
        dep_files, frameworks = parse_dependencies(code_root)
        entrypoints = find_entrypoints(code_root)
        tree = build_tree(code_root, files)
        return {
            "languages": languages,
            "frameworks": frameworks,
            "dependencies": dep_files,
            "entrypoints": entrypoints,
            "file_count": len(files),
            "loc": loc,
            "tree": tree,
            "_files": [str(f) for f in files],  # 供后续扫描/审计使用
        }

    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：parse.request → parse.result。

        输入 payload.code_root（缺省回退 context.code_root）；
        输出 payload.metadata 为完整元信息结构（languages/frameworks/dependencies/
        entrypoints/file_count/loc），payload._files 保留文件清单供后续阶段复用。
        """
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState

        code_root_str = request.payload.get("code_root") or request.context.code_root
        if not code_root_str:
            return make_reply(
                request, sender=self.name,
                message_type=ACPMessageType.PARSE_RESULT,
                intent="缺少 code_root，无法解析仓库",
                state=ACPState.FAILED, error="missing code_root",
            )
        raw_max_files = request.payload.get("max_files") or 20000
        try:
            max_files = max(1, min(int(raw_max_files), 200000))
        except (TypeError, ValueError):
            max_files = 20000
        self._max_files = max_files
        metadata = self.run(Path(code_root_str))
        # 标准元信息（去掉 _ 前缀的内部字段），文件清单单列，避免污染 metadata
        public_meta = {k: v for k, v in metadata.items() if not k.startswith("_")}
        return make_reply(
            request, sender=self.name,
            message_type=ACPMessageType.PARSE_RESULT,
            intent=f"仓库解析完成：{metadata.get('file_count', 0)} 个文件",
            payload={"metadata": public_meta, "_files": metadata.get("_files", [])},
            state=ACPState.SUCCESS,
        )
