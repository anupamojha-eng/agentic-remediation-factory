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

    # Well-known GHSA IDs mapped to the dangerous Java call-site patterns they require.
    # Checked first (fast + reliable) before falling back to the LLM for unknowns.
    _KNOWN_PATTERNS: dict = {
        # jackson-databind polymorphic typing RCE family
        "GHSA-jjjh-jjxp-wpff": ["enableDefaultTyping"],
        "GHSA-rgv9-q543-rqg4": ["enableDefaultTyping"],
        "GHSA-3x8x-79m2-3w2w": ["enableDefaultTyping"],
        "GHSA-57j2-w4cx-62h2": ["enableDefaultTyping"],
        # snakeyaml deserialization RCE family
        "GHSA-668q-qrv7-99fm": ["new Yaml()"],
        "GHSA-735f-pc8j-v9w8": ["new Yaml()"],
        # commons-text Text4Shell
        "GHSA-599f-7c49-w659": ["new StringSubstitutor"],
        # Log4Shell family
        "GHSA-jfh8-c2jp-hdp8": ["MDC.put", "ThreadContext.put"],
        "GHSA-7rjr-3q55-vv33": ["MDC.put", "ThreadContext.put"],
        # Kafka unsafe deserialization
        "GHSA-26f8-x96c-9785": ["new KafkaConsumer", "StringDeserializer"],
        "GHSA-gg5e-p4p8-6hjm": ["Deserializer"],
    }

    def get_vulnerable_patterns(self, ghsa_ids: list) -> list:
        """
        Return grep patterns for Java code that makes these CVEs exploitable.
        Checks the known-pattern map first (fast + reliable), then falls back
        to the LLM for CVEs not in the map.
        """
        patterns: set = set()
        unknown = []

        for ghsa in ghsa_ids:
            if ghsa in self._KNOWN_PATTERNS:
                patterns.update(self._KNOWN_PATTERNS[ghsa])
            else:
                unknown.append(ghsa)

        if unknown:
            prompt = f"""These Java security vulnerabilities were found in a project:
{unknown}

For each one that is exploitable via a specific dangerous Java code pattern,
give the grep string that identifies that call site in .java source files.

Reference examples:
  Jackson enableDefaultTyping RCE -> grep: enableDefaultTyping
  SnakeYAML deserialization RCE   -> grep: new Yaml()
  Commons-text Text4Shell         -> grep: new StringSubstitutor
  Log4Shell JNDI via MDC          -> grep: MDC.put
  Kafka unsafe Deserializer       -> grep: Deserializer

Return ONLY a JSON array of grep strings. [] if purely library-internal."""

            try:
                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction="Return ONLY a raw JSON array of strings. No markdown.",
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
                    patterns.update(p for p in result if isinstance(p, str))
            except Exception as e:
                print(f"  Pattern detection error: {e}")

        return list(patterns)

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
