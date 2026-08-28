"""OpenAI 兼容 LLM 客户端。

使用 openai SDK，通过 base_url 对接任意 OpenAI 兼容接口
（OpenAI / DeepSeek / 通义千问 / Moonshot / Ollama 等）。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Optional

import httpx
from openai import APIConnectionError, APITimeoutError, AsyncOpenAI

from ..config import settings

# 记录最近一次 LLM 调用是否命中响应缓存（供任务收尾时透出给前端展示）。
# 每次建模任务的 4 次 LLM 调用在单任务内串行执行，因此模块级标志是安全的；
# 任务结束由 router 读取后重置，避免污染下一次任务。
_LAST_CACHE_HIT: list[bool] = [False]


def set_last_cache_hit(hit: bool) -> None:
    _LAST_CACHE_HIT[0] = hit


def last_cache_hit() -> bool:
    return _LAST_CACHE_HIT[0]


def _hash_images(images: list[str]) -> str:
    """对多模态图片 data URI 计算内容摘要，用于缓存键。

    同一份文档提取出的图片字节一致 → 摘要一致 → 命中缓存；
    换图/重新编码 → 摘要不同 → miss 重新生成。
    只取每张图 sha256 前 16 位 hex（64bit，碰撞概率可忽略），多图用分号连接，
    避免超大 key。
    """
    parts = []
    for uri in images:
        if not uri:
            continue
        parts.append(hashlib.sha256(uri.encode("utf-8", "ignore")).hexdigest()[:16])
    return ";".join(parts)


class LLMClient:
    """封装 OpenAI 兼容 API 的调用，支持结构化 JSON 输出。

    可通过 ``overrides`` 传入前端界面提供的模型配置
    （base_url / api_key / model），优先于 .env 中的默认值。
    """

    _PLACEHOLDER_KEYS = (
        "sk-your-",
        "your-",
        "placeholder",
        "change-me",
        "changeme",
        "your_api_key",
    )

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        # 前端界面传入的配置优先，否则回退到 .env
        api_key = api_key or settings.llm_api_key
        base_url = base_url or settings.llm_base_url
        self.base_url = base_url
        self.model = model or settings.llm_model
        self.temperature = settings.llm_temperature
        # 生成稳定性：固定种子（0 表示由服务商随机，等价不传）
        self.seed = settings.llm_seed

        if not api_key:
            raise ValueError(
                "缺少 LLM API Key。请在顶部「配置模型」中填写，或在 backend/.env 中配置。"
            )

        # 拦截 .env 占位符——这种情况说明后端其实没真正配置 LLM
        low = api_key.lower()
        if any(p in low for p in self._PLACEHOLDER_KEYS):
            raise ValueError(
                "检测到 API Key 仍是 .env 中的占位符（sk-your-…）。"
                "请在顶部「配置模型」中粘贴真实的 Key，或修改 backend/.env 中的 LLM_API_KEY 后重启服务。"
            )
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            # 网络层显式超时，避免长时间挂起（连接 10s，读取 3 分钟）
            timeout=httpx.Timeout(180.0, connect=10.0),
            max_retries=settings.llm_max_retries,
        )

    @staticmethod
    def _truncate_text(
        text: str,
        max_chars: int = 12000,
        head_ratio: float = 0.6,
    ) -> str:
        """按字符数估算 token 并截断超长文本。

        使用保守估算（每字符约 0.4 token，中文偏高），避免超长文档
        直接打爆模型上下文窗口。保留头部较大比例，尾部保留摘要。
        """
        if not text or len(text) <= max_chars:
            return text
        head_len = int(max_chars * head_ratio)
        tail_len = max_chars - head_len
        return (
            text[:head_len]
            + f"\n\n……[内容过长，已截断，共 {len(text)} 字符]……\n\n"
            + text[-tail_len:]
        )

    @staticmethod
    def _robust_parse_json(content: str) -> dict[str, Any]:
        """健壮地从 LLM 返回文本中解析 JSON 对象。

        依次尝试：
        1. 直接 json.loads；
        2. 去掉 ```json ... ``` 代码块围栏后解析；
        3. 用大括号配对截取首个最外层 JSON 对象；
        4. 尝试修复截断的结尾（补全右括号）。
        """
        text = content.strip()
        if not text:
            raise ValueError("LLM 返回为空")

        def _try_parse(s: str) -> dict[str, Any] | None:
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                return None
            return None

        # 1) 直接解析
        if _try_parse(text):
            return _try_parse(text)

        # 2) 去掉代码块围栏
        if text.startswith("```"):
            cleaned = text.strip("`").strip()
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].strip()
            obj = _try_parse(cleaned)
            if obj:
                return obj
            text = cleaned

        # 3) 截取首个最外层 JSON 对象（应对前后有解释性文本）
        start = text.find("{")
        if start != -1:
            depth = 0
            in_str = False
            escape = False
            for i in range(start, len(text)):
                ch = text[i]
                if in_str:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        obj = _try_parse(text[start : i + 1])
                        if obj:
                            return obj
                        break

        # 4) 尝试补全截断的结尾（缺右括号）
        if start != -1:
            candidate = text[start:]
            for _ in range(8):
                candidate += "}"
                obj = _try_parse(candidate)
                if obj:
                    return obj

        raise ValueError(f"LLM 返回内容无法解析为 JSON: {content[:300]}")

    @staticmethod
    def _raise_connection_error(exc: Exception, base_url: str) -> None:
        """把 openai/httpx 的连接类异常转成含地址的中文 RuntimeError。"""
        if isinstance(exc, (httpx.TimeoutException, APITimeoutError)):
            raise RuntimeError(
                f"连接 LLM 服务 {base_url!r} 超时。"
                "请检查该地址的网络连通性，或确认服务已启动（如 codebuddy2api 需先运行）。"
            ) from exc
        raise RuntimeError(
            f"无法连接到 LLM 服务 {base_url!r}。"
            "请检查 API 地址是否正确、服务是否已启动、网络是否可达。"
        ) from exc

    async def _create_with_patch(
        self,
        kwargs: dict[str, Any],
        patch: dict[str, Any],
        pure_text: str | None = None,
    ) -> Any:
        """按补丁浅拷贝 kwargs 并调用 chat.completions.create，避免污染原始参数。

        支持两种补丁：
        - patch["messages"] = None 且提供 pure_text：把多模态 user content 换成纯文本；
        - patch["response_format"] = None：删除 response_format（触发降级）。
        """
        new_kwargs = dict(kwargs)
        if "messages" in patch and patch["messages"] is None and pure_text is not None:
            new_kwargs["messages"] = list(kwargs["messages"])
            new_kwargs["messages"][1] = {"role": "user", "content": pure_text}
        if "response_format" in patch:
            if patch["response_format"] is None:
                new_kwargs.pop("response_format", None)
            else:
                new_kwargs["response_format"] = patch["response_format"]
        return await self.client.chat.completions.create(**new_kwargs)

    @staticmethod
    def _is_schema_unsupported(exc: Exception) -> bool:
        """判断异常是否因服务商不支持 json_schema 结构化输出导致。"""
        msg = str(exc).lower()
        # 同时检查 HTTP 状态码（OpenAI SDK 的 APIStatusError 有 status_code 属性）
        status_code = getattr(exc, "status_code", None)
        if status_code == 400:
            return True
        markers = (
            "response_format",
            "json_schema",
            "json schema",
            "structured output",
            "unsupported",
            "not supported",
            "bad_request",
            "invalid_parameter",
            "400",
        )
        return any(m in msg for m in markers)

    @staticmethod
    def _is_image_unsupported(exc: Exception) -> bool:
        """判断异常是否因模型不支持图片（多模态输入）导致。

        识别 ``does not support image`` / ``not supported`` / ``image`` 等常见文案，
        或 OpenAI SDK 的 ``invalid_request_error`` 400 错误。一旦命中，后续所有降级
        都应去掉图片，避免每次带图调用重复撞同一 400 错误。
        """
        msg = str(exc).lower()
        if "image" not in msg:
            return False
        return any(
            m in msg
            for m in (
                "does not support",
                "doesn't support",
                "not supported",
                "unsupported",
                "invalid_request_error",
            )
        )

    async def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        max_input_chars: int = 12000,
        json_schema: dict[str, Any] | None = None,
        images: list[str] | None = None,
    ) -> dict[str, Any]:
        """调用 LLM 并解析为 JSON 对象。

        稳定性策略：
        - 固定 ``seed`` + 低温，保证同模型同输入结果可复现；
        - 可选 ``json_schema``：服务商支持结构化输出时强约束字段与枚举；
        - 命中 LLM 响应缓存时直接返回，跳过 API 调用（同输入字节级一致）。

        Args:
            system_prompt: 系统提示词，用于约束输出格式。
            user_prompt: 用户输入内容。
            json_schema: 可选的 JSON Schema，用于结构化输出约束。
            images: 可选的图片 data URI 列表（多模态）。含图时缓存键会
                附加图片内容哈希（同图同文本 → 命中缓存，结果可复现）；
                模型不支持图片时自动降级为纯文本重试。

        Returns:
            解析后的 JSON 对象。

        Raises:
            RuntimeError: 当模型返回非 JSON 内容或调用失败时。
        """
        # 命中缓存：同一 model+seed+prompt+schema(+图片内容哈希) 直接返回，保证跨 run 稳定
        # 含图时也不再跳过缓存——把图片内容哈希纳入缓存键：同一份文档
        # 提取出的图片字节一致 → 命中缓存，结果完全可复现；换图才 miss 重新生成。
        from .llm_cache import get_llm_cache, record_cache_key

        cache = get_llm_cache()
        truncated_user = self._truncate_text(user_prompt, max_input_chars)
        has_images = bool(images)
        images_hash = _hash_images(images) if has_images else None
        cache_key = cache.build_key(
            system_prompt,
            truncated_user,
            self.model,
            self.seed,
            json_schema,
            images_hash=images_hash,
            temperature=self.temperature,
        )
        hit = cache.get(cache_key)
        if hit is not None:
            # 命中也要记录键：删除结果时需能失效"本次只是命中"的缓存
            record_cache_key(cache_key)
            set_last_cache_hit(True)
            return hit

        # 构造 user content：纯文本字符串，或「文本 + 多模态图片」数组
        user_content: Any = truncated_user
        if has_images:
            parts: list[Any] = [{"type": "text", "text": truncated_user}]
            for uri in images:
                if uri and uri.startswith("data:"):
                    parts.append(
                        {"type": "image_url", "image_url": {"url": uri}}
                    )
            user_content = parts

        kwargs: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }
        # 固定种子（部分国产模型不支持时可在 .env 里 LLM_SEED=0 关闭）
        if self.seed:
            kwargs["seed"] = self.seed
        # 结构化输出：服务商支持 json_schema 时使用；否则退回 json_object
        use_schema = json_schema is not None
        if use_schema:
            kwargs["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "structured_output",
                    "strict": True,
                    "schema": json_schema,
                },
            }
        else:
            kwargs["response_format"] = {"type": "json_object"}

        set_last_cache_hit(False)  # 未命中缓存，即将发起真实 LLM 调用
        response: Any = None
        try:
            response = await self.client.chat.completions.create(**kwargs)
        except (httpx.ConnectError, httpx.TimeoutException, APIConnectionError) as exc:
            self._raise_connection_error(exc, self.base_url)
        except Exception as exc:
            # 依次尝试以下降级策略，直到成功或全部失败：
            #   图片不支持 → 去掉图片只留文本
            #   json_schema → 降级 json_object
            #   response_format → 完全移除 response_format，只靠系统提示词约束
            #
            # 关键：一旦首调因“模型不支持图片”失败，后续所有降级都必须保持无图，
            # 否则降级 2/3 又带图重试，会反复撞同一 400 错误（“已尝试 N+1 种方式均失败”）。
            last_exc = exc
            skip_images = has_images and self._is_image_unsupported(exc)

            def make_attempt(label: str, patch: dict[str, Any]) -> tuple[str, Callable[[], Any]]:
                """构造一次降级尝试；若需去图，则在补丁上强制附加 messages=None。"""
                effective = dict(patch)
                if skip_images and "messages" not in effective:
                    effective["messages"] = None
                if "messages" in effective:
                    return (
                        label,
                        lambda: self._create_with_patch(
                            kwargs, effective, truncated_user,
                        ),
                    )
                return (
                    label,
                    lambda: self._create_with_patch(kwargs, effective),
                )

            attempts: list[tuple[str, Callable[[], Any]]] = []
            # 降级 1：含图 → 去掉图片只留文本（保留当前 response_format）
            if has_images:
                attempts.append(make_attempt("去掉图片仅用文本", {"messages": None}))
            # 降级 2：json_schema → json_object（图片问题场景同样去图）
            if use_schema:
                attempts.append(make_attempt(
                    "降级为 json_object",
                    {"response_format": {"type": "json_object"}},
                ))
            # 降级 3：完全移除 response_format（图片问题场景同样去图）
            attempts.append(make_attempt(
                "移除 response_format",
                {"response_format": None},
            ))

            for label, fn in attempts:
                try:
                    response = await fn()
                    break
                except (httpx.ConnectError, httpx.TimeoutException, APIConnectionError) as exc2:
                    self._raise_connection_error(exc2, self.base_url)
                except Exception as exc2:
                    last_exc = exc2
                    response = None
            if response is None:
                raise RuntimeError(
                    f"LLM 调用失败（已尝试 {len(attempts)}+1 种方式均失败）: {last_exc}"
                ) from last_exc
        content = response.choices[0].message.content or ""
        try:
            result = self._robust_parse_json(content)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

        if cache_key is not None:
            cache.set(cache_key, result)
        return result

    async def complete_text(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """调用 LLM 返回纯文本。"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except (httpx.ConnectError, httpx.TimeoutException, APIConnectionError) as exc:
            self._raise_connection_error(exc, self.base_url)
        return response.choices[0].message.content or ""
