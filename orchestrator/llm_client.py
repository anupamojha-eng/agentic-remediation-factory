import os
import json
import re as _re
from google import genai
from google.genai import types
import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
provider = MeterProvider(metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter("remediation.agent")

latency_hist = meter.create_histogram("llm_latency", unit="ms")
token_counter = meter.create_counter("llm_tokens_total")


def _is_java_compile_error(build_error: str) -> bool:
    return bool(_re.search(r'\S+\.java:\[?\d+', build_error or ""))


class SecurityAgentClient:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment.")

        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.5-flash"

    def get_vulnerable_patterns(self, ghsa_ids: list) -> list:
        """
        Given a list of GHSA IDs, return grep patterns for Java code that makes
        these CVEs actively exploitable (not just having the vulnerable dep).
        Returns an empty list if no exploitable code patterns exist.
        """
        prompt = f"""These security vulnerabilities were found in a Java project:
{ghsa_ids}

For each vulnerability, what Java source code PATTERNS would make the code actively exploitable
(e.g. calling a specific API in a dangerous way, not just having the library)?

Return ONLY a JSON array of grep strings to search for in .java files.
Examples:
- SnakeYAML deserialization: ["new Yaml()"]
- Jackson default typing: ["enableDefaultTyping"]
- XStream unsafe: ["XStream()"]
- Log4j JNDI lookup context: ["MDC.put", "ThreadContext.put"]

If these CVEs are pure library-internal issues with no dangerous call site pattern,
return an empty array: []

Return ONLY the JSON array of strings, nothing else."""

        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction="Return ONLY a raw JSON array. No markdown, no explanation.",
                    temperature=0.0
                )
            )
            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            result = json.loads(text.strip())
            if isinstance(result, list):
                return [p for p in result if isinstance(p, str)]
        except Exception as e:
            print(f"  Pattern detection error: {e}")
        return []

    def get_remediation_plan(self, ghsa_ids, files_content, build_system="maven", build_error=None):
        """
        files_content: dict of {filename: content}
        Returns: {"patches": {filename: patched_content}, "changes": [...], "analysis": "..."}
        """
        start = time.time()

        files_section = "\n".join(
            f"\n### {fn}\n```\n{content}\n```" for fn, content in files_content.items()
        )

        if build_error and _is_java_compile_error(build_error):
            user_prompt = self._compile_fix_prompt(ghsa_ids, build_system, build_error, files_section)
            system_instructions = (
                "You are a Java engineer fixing compilation errors. "
                "Return ONLY a raw JSON object — no preamble, no markdown fences. "
                "You MUST return a 'patches' entry for every .java file that appears in the errors."
            )
        else:
            user_prompt = self._cve_fix_prompt(ghsa_ids, build_system, build_error, files_section)
            system_instructions = (
                "You are a Senior Security Engineer. Return ONLY a raw JSON object. "
                "Do not include any preamble, explanation, or markdown code blocks."
            )

        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instructions,
                    temperature=0.1
                )
            )

            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            duration = (time.time() - start) * 1000
            latency_hist.record(duration, {"model": self.model_id})

            usage = response.usage_metadata
            token_counter.add(usage.prompt_token_count, {"type": "prompt"})
            token_counter.add(usage.candidates_token_count, {"type": "completion"})

            return json.loads(text.strip())
        except Exception as e:
            print(f"LLM Inference Error: {e}")
            return None

    def _cve_fix_prompt(self, ghsa_ids, build_system, build_error, files_section):
        error_section = ""
        if build_error:
            error_section = (
                f"\nPREVIOUS PATCH ATTEMPT FAILED. The build broke with this error:\n"
                f"```\n{build_error}\n```\n"
                f"You MUST produce a more conservative patch. Prefer the smallest safe version "
                f"upgrade that fixes each vulnerability. Do NOT upgrade dependencies whose new "
                f"version introduces API incompatibilities visible in the error above."
            )

        return f"""Fix the following security vulnerabilities in the provided build file(s).

GHSAs to fix: {ghsa_ids}
Build system: {build_system}
{error_section}
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
- For *.java source files: implement missing abstract methods (minimal stub throwing
  UnsupportedOperationException for read-only adapters), fix incompatible type casts,
  and update deprecated/removed API calls. Return the COMPLETE file content.
"""

    def _compile_fix_prompt(self, ghsa_ids, build_system, build_error, files_section):
        return f"""This {build_system} project has TWO problems you must fix in one pass:
1. Security vulnerabilities: {ghsa_ids} — fix by upgrading the vulnerable dependencies in the build file.
2. Compilation errors that prevent the project from building.

You must return patches for BOTH the build file (dependency upgrades) AND every failing Java source file.

COMPILATION ERRORS:
```
{build_error}
```

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
   - CRITICAL: copy the parameter types verbatim from the error message — if the error
     says (int,int,int,int,int) use five ints, NOT PaneType; if it says (PageMargin)
     use PageMargin, NOT short or int.
   - Body: throw new UnsupportedOperationException("Not supported by streaming reader");
   - Add any necessary imports for the parameter types.
3. For every error "incompatible types: A cannot be converted to B":
   - Keep the existing variable type B. Add an explicit cast: (B) expression.
4. For every error "cannot find symbol: class X":
   - Add the correct import statement for X.
5. For each .java file with errors: fix ALL its errors in one pass.
6. You MUST include a "patches" entry for every .java file in the errors above.
"""
