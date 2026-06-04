"""
LLM provider abstraction for Sentinel.

Supports Anthropic (Claude) and Google (Gemini). Provider is auto-detected
from environment variables or forced via LLM_PROVIDER=anthropic|gemini.

Priority: ANTHROPIC_API_KEY > GEMINI_API_KEY (Claude is preferred for complex
multi-file code reasoning; Gemini Flash is a cost-effective alternative).

Prompt caching (Anthropic only): on retry calls the expensive `rules + file
contents` block is served from cache; only the new build error is billed at
full price. This saves ~80-90% of input tokens on the second and third attempts.
"""
import os
import json
import re as _re
import time

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
meter = metrics.get_meter("remediation.agent")
latency_hist = meter.create_histogram("llm_latency", unit="ms")
token_counter = meter.create_counter("llm_tokens_total")


# ── Provider abstraction ───────────────────────────────────────────────────────

class _LLMProvider:
    model_id: str = ""

    def generate(self, system: str, user: str) -> str:
        """Single-block generate — no caching."""
        raise NotImplementedError

    def generate_cached(self, system: str, cacheable_user: str, volatile_user: str = "") -> str:
        """
        Two-block generate: `cacheable_user` is marked for caching (stable across
        retries); `volatile_user` is appended uncached (changes per retry).

        Falls back to simple generate if the provider doesn't support caching.
        """
        combined = cacheable_user + ("\n\n" + volatile_user if volatile_user else "")
        return self.generate(system, combined)

    def record_tokens(self, prompt_tokens: int, completion_tokens: int):
        token_counter.add(prompt_tokens, {"type": "prompt", "model": self.model_id})
        token_counter.add(completion_tokens, {"type": "completion", "model": self.model_id})


class _GeminiProvider(_LLMProvider):
    def __init__(self):
        from google import genai
        from google.genai import types as _types
        self._types = _types
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
        self._client = genai.Client(api_key=api_key)
        self.model_id = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        print(f"  [LLM] Gemini provider: {self.model_id}")

    def generate(self, system: str, user: str) -> str:
        resp = self._client.models.generate_content(
            model=self.model_id,
            contents=user,
            config=self._types.GenerateContentConfig(
                system_instruction=system,
                temperature=0.1,
            ),
        )
        usage = resp.usage_metadata
        self.record_tokens(
            usage.prompt_token_count or 0,
            usage.candidates_token_count or 0,
        )
        return resp.text


class _AnthropicProvider(_LLMProvider):
    def __init__(self):
        import anthropic as _sdk
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        self._client = _sdk.Anthropic(api_key=api_key)
        self.model_id = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8")
        print(f"  [LLM] Anthropic provider: {self.model_id}")

    def generate(self, system: str, user: str) -> str:
        resp = self._client.messages.create(
            model=self.model_id,
            max_tokens=8192,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        self.record_tokens(resp.usage.input_tokens, resp.usage.output_tokens)
        return resp.content[0].text

    def generate_cached(self, system: str, cacheable_user: str, volatile_user: str = "") -> str:
        """
        Marks `cacheable_user` with cache_control so it's cached across retries.
        When Sentinel retries a failed patch, `cacheable_user` (rules + file
        contents) is served from cache; only `volatile_user` (the new build
        error) is billed at full price.

        Cache fires when the block exceeds the model's minimum (~4096 tokens for
        Opus, ~2048 for Sonnet). File contents typically push us well past that.
        """
        content = [
            {
                "type": "text",
                "text": cacheable_user,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        if volatile_user:
            content.append({"type": "text", "text": volatile_user})

        resp = self._client.messages.create(
            model=self.model_id,
            max_tokens=8192,
            system=system,
            messages=[{"role": "user", "content": content}],
        )
        u = resp.usage
        self.record_tokens(u.input_tokens, u.output_tokens)
        cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
        cache_write = getattr(u, "cache_creation_input_tokens", 0) or 0
        if cache_read or cache_write:
            print(f"  [cache] read={cache_read} write={cache_write} uncached={u.input_tokens}")
        return resp.content[0].text


def _make_provider() -> _LLMProvider:
    """Select provider from env vars. Anthropic wins when both keys are set."""
    forced = os.getenv("LLM_PROVIDER", "").lower()
    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
    has_gemini = bool(os.getenv("GEMINI_API_KEY"))

    if forced == "anthropic" or (not forced and has_anthropic):
        return _AnthropicProvider()
    if forced == "gemini" or (not forced and has_gemini):
        return _GeminiProvider()
    raise ValueError(
        "No LLM API key found. Set ANTHROPIC_API_KEY (Claude) or GEMINI_API_KEY (Gemini). "
        "Optionally set LLM_PROVIDER=anthropic|gemini to force a provider when both are set."
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_java_compile_error(build_error: str) -> bool:
    return bool(_re.search(r'\S+\.java:\[?\d+', build_error or ""))


def _is_python_error(build_error: str) -> bool:
    return bool(_re.search(r'File ".*\.py"', build_error or ""))


def _strip_json_fences(text: str) -> str:
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    return text.strip()


# ── Main client ────────────────────────────────────────────────────────────────

class SecurityAgentClient:
    # Well-known GHSA IDs → dangerous call-site grep patterns (Java and Python).
    # Checked first (fast + reliable) before falling back to the LLM for unknowns.
    _KNOWN_PATTERNS: dict = {
        # ── Java: jackson-databind polymorphic typing RCE ─────────────────────
        "GHSA-jjjh-jjxp-wpff": ["enableDefaultTyping"],
        "GHSA-rgv9-q543-rqg4": ["enableDefaultTyping"],
        "GHSA-3x8x-79m2-3w2w": ["enableDefaultTyping"],
        "GHSA-57j2-w4cx-62h2": ["enableDefaultTyping"],
        # ── Java: snakeyaml deserialization RCE ──────────────────────────────
        "GHSA-668q-qrv7-99fm": ["new Yaml()"],
        "GHSA-735f-pc8j-v9w8": ["new Yaml()"],
        # ── Java: commons-text Text4Shell ─────────────────────────────────────
        "GHSA-599f-7c49-w659": ["new StringSubstitutor"],
        # ── Java: Log4Shell ───────────────────────────────────────────────────
        "GHSA-jfh8-c2jp-hdp8": ["MDC.put", "ThreadContext.put"],
        "GHSA-7rjr-3q55-vv33": ["MDC.put", "ThreadContext.put"],
        # ── Java: Kafka unsafe deserialization ───────────────────────────────
        "GHSA-26f8-x96c-9785": ["new KafkaConsumer", "StringDeserializer"],
        "GHSA-gg5e-p4p8-6hjm": ["Deserializer"],
        # ── Python: PyYAML unsafe load ────────────────────────────────────────
        "GHSA-8q59-q68h-6hv4": ["yaml.load("],
        "GHSA-6q5r-27gj-jm84": ["yaml.load("],
        "GHSA-rprw-h62v-c2w7": ["yaml.load("],
        # ── Python: pickle deserialization RCE ───────────────────────────────
        "GHSA-8mpf-9jhm-48r3": ["pickle.loads(", "pickle.load("],
        # ── Python: Jinja2 sandbox escape ────────────────────────────────────
        "GHSA-g3rq-g295-4j3m": ["render_template_string(", "Environment("],
        "GHSA-h5c8-rqwp-cp95": ["render_template_string("],
    }

    _PYTHON_ALWAYS_CHECK: list = [
        "yaml.load(",
        "pickle.loads(",
        "pickle.load(",
    ]

    _JAVA_ALWAYS_CHECK: list = [
        "new ObjectInputStream(",             # Java deserialization RCE (equivalent of pickle)
        "Runtime.getRuntime().exec(",          # OS command injection
        "new ProcessBuilder(",                 # OS command injection
        'MessageDigest.getInstance("MD5"',     # weak hashing
        'MessageDigest.getInstance("SHA-1"',   # weak hashing
        "new Random(",                         # insecure randomness — use SecureRandom
        "DocumentBuilderFactory.newInstance(", # XML External Entity (XXE)
        "XMLInputFactory.newInstance(",        # XXE
    ]

    def __init__(self):
        self.llm = _make_provider()
        self.model_id = self.llm.model_id  # kept for OTel label compatibility

    def get_vulnerable_patterns(self, ghsa_ids: list, build_system: str = "maven") -> list:
        """
        Return grep patterns for source files that make these CVEs exploitable.
        Checks the known-pattern map first, then falls back to the LLM.
        Returns an ordered list: _PYTHON_ALWAYS_CHECK first, then known patterns, then LLM.
        """
        # Use ordered list + seen-set to preserve priority and deduplicate
        patterns: list = []
        seen: set = set()

        def _add(p):
            if p not in seen:
                patterns.append(p)
                seen.add(p)

        if build_system == "python":
            for p in self._PYTHON_ALWAYS_CHECK:
                _add(p)
        elif build_system in ("maven", "gradle"):
            for p in self._JAVA_ALWAYS_CHECK:
                _add(p)

        unknown = []
        for ghsa in ghsa_ids:
            if ghsa in self._KNOWN_PATTERNS:
                for p in self._KNOWN_PATTERNS[ghsa]:
                    _add(p)
            else:
                unknown.append(ghsa)

        if unknown:
            lang = "Python" if build_system == "python" else "Java"
            ext = ".py" if build_system == "python" else ".java"
            prompt = f"""These {lang} security vulnerabilities were found in a project:
{unknown}

For each one exploitable via a specific dangerous {lang} code pattern,
give the grep string that identifies that call site in {ext} source files.

Reference examples ({lang}):
  {"PyYAML unsafe load -> grep: yaml.load(" if build_system == "python" else "Jackson enableDefaultTyping RCE -> grep: enableDefaultTyping"}
  {"pickle deserialization -> grep: pickle.loads(" if build_system == "python" else "SnakeYAML deserialization RCE -> grep: new Yaml()"}
  {"subprocess shell injection -> grep: shell=True" if build_system == "python" else "Commons-text Text4Shell -> grep: new StringSubstitutor"}

Return ONLY a JSON array of grep strings. [] if purely library-internal."""

            try:
                text = self.llm.generate(
                    system="Return ONLY a raw JSON array of strings. No markdown.",
                    user=prompt,
                )
                result = json.loads(_strip_json_fences(text))
                if isinstance(result, list):
                    for p in result:
                        if isinstance(p, str):
                            _add(p)
            except Exception as e:
                print(f"  Pattern detection error: {e}")

        return patterns

    def get_remediation_plan(self, ghsa_ids, files_content, build_system="maven", build_error=None):
        """
        files_content: dict of {filename: content}
        Returns: {"patches": {filename: patched_content}, "changes": [...], "analysis": "..."}
        """
        start = time.time()

        files_section = "\n".join(
            f"\n### {fn}\n```\n{content}\n```" for fn, content in files_content.items()
        )

        is_compile_error = build_error and _is_java_compile_error(build_error)

        if is_compile_error:
            system = (
                "You are a Java engineer fixing compilation errors. "
                "Return ONLY a raw JSON object — no preamble, no markdown fences. "
                "You MUST return a 'patches' entry for every .java file in the errors."
            )
            cacheable, volatile = self._compile_fix_prompt(
                ghsa_ids, build_system, build_error, files_section
            )
        else:
            system = (
                "You are a Senior Security Engineer. "
                "Return ONLY a raw JSON object. "
                "No preamble, explanation, or markdown code blocks."
            )
            cacheable, volatile = self._cve_fix_prompt(
                ghsa_ids, build_system, build_error, files_section
            )

        try:
            text = self.llm.generate_cached(system, cacheable, volatile)
            duration_ms = (time.time() - start) * 1000
            latency_hist.record(duration_ms, {"model": self.model_id})
            return json.loads(_strip_json_fences(text))
        except Exception as e:
            print(f"LLM Inference Error: {e}")
            return None

    # ── Prompt builders (return cacheable_block, volatile_block) ──────────────

    def _cve_fix_prompt(
        self, ghsa_ids, build_system, build_error, files_section
    ) -> tuple[str, str]:
        """
        Returns (cacheable, volatile).

        cacheable = rules + file contents  → stable across retry attempts
        volatile  = error section          → changes each retry
        """
        cacheable = f"""Fix the following security vulnerabilities in the provided build/source file(s).

GHSAs to fix: {ghsa_ids}
Build system: {build_system}

Files to analyze and patch:
{files_section}

Return ONLY a JSON object in this exact format:
{{
    "patches": {{
        "<filename>": "<complete patched file content>"
    }},
    "changes": ["specific change descriptions"],
    "analysis": "brief explanation of fixes"
}}

Rules:
- Each value in "patches" must be the COMPLETE file content with all fixes applied
- Only include files that actually need to be changed in "patches"
- For pom.xml: update <dependency> version tags, <parent> version, BOM import versions, and <properties> version variables
- For build.gradle: update version strings in dependency declarations, ext/def version variables, and platform BOM imports
- For build.gradle.kts: same as above but Kotlin DSL syntax (double-quoted strings, val declarations)
- For gradle/libs.versions.toml: update version values in the [versions] table
- Only change what is necessary to fix the specified vulnerabilities
- Prefer the minimum version that fixes the vulnerability — avoid unnecessary major upgrades
- Preserve all formatting, whitespace, comments, and file structure exactly
- For requirements.txt / Pipfile / pyproject.toml: update version pins to the minimum safe version
- For *.py source files:
    - Replace yaml.load(data) or yaml.load(f) with yaml.safe_load(data) / yaml.safe_load(f)
    - Replace yaml.load(data, Loader=yaml.Loader) with yaml.safe_load(data)
    - Add a security comment if pickle.loads() cannot be safely removed
    - Replace subprocess calls with shell=True with list-form when input may be user-controlled
- For *.java source files: implement missing abstract methods (minimal stub throwing
  UnsupportedOperationException for read-only adapters), fix incompatible type casts,
  and update deprecated/removed API calls. Return the COMPLETE file content."""

        volatile = ""
        if build_error:
            volatile = (
                f"\nPREVIOUS PATCH ATTEMPT FAILED. The build broke with this error:\n"
                f"```\n{build_error}\n```\n"
                f"Produce a more conservative patch. Prefer the smallest safe version upgrade "
                f"that fixes each vulnerability. Do NOT upgrade dependencies whose new version "
                f"introduces API incompatibilities visible in the error above."
            )

        return cacheable, volatile

    def _compile_fix_prompt(
        self, ghsa_ids, build_system, build_error, files_section
    ) -> tuple[str, str]:
        """
        Returns (cacheable, volatile).

        cacheable = task description + file contents (stable across retries)
        volatile  = the compilation errors (changes as source files are fixed)
        """
        cacheable = f"""This {build_system} project has TWO problems you must fix in one pass:
1. Security vulnerabilities: {ghsa_ids} — fix by upgrading the vulnerable dependencies in the build file.
2. Compilation errors that prevent the project from building.

You must return patches for BOTH the build file (dependency upgrades) AND every failing Java source file.

Current file contents (some already partially patched):
{files_section}

Return ONLY a JSON object in this exact format:
{{
    "patches": {{
        "<filename>": "<complete patched file content>"
    }},
    "changes": ["one line per fix describing what was changed and why"],
    "analysis": "brief summary"
}}

Rules — apply ALL of these to fix every error listed above:
1. Keep build files at their CURRENT version (the upgrade is correct — do NOT revert).
2. For every error "does not override abstract method M(T1, T2, ...)":
   - The error message shows the EXACT signature you must implement.
   - Add that EXACT method with that EXACT parameter list to the class body.
   - CRITICAL: copy the parameter types verbatim from the error message.
   - Body: throw new UnsupportedOperationException("Not supported by streaming reader");
   - Add any necessary imports for the parameter types.
3. For every error "incompatible types: A cannot be converted to B":
   - Keep the existing variable type B. Add an explicit cast: (B) expression.
4. For every error "cannot find symbol: class X":
   - Add the correct import statement for X.
5. For each .java file with errors: fix ALL its errors in one pass.
6. You MUST include a "patches" entry for every .java file in the errors above."""

        volatile = f"\nCOMPILATION ERRORS:\n```\n{build_error}\n```"

        return cacheable, volatile
