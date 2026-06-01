import os
import json
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


class SecurityAgentClient:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment.")

        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.5-flash"

    def get_remediation_plan(self, ghsa_ids, files_content, build_system="maven", build_error=None):
        """
        files_content: dict of {filename: content} e.g. {"pom.xml": "...", "gradle/libs.versions.toml": "..."}
        Returns: {"patches": {filename: patched_content}, "changes": [...], "analysis": "..."}
        """
        start = time.time()

        system_instructions = (
            "You are a Senior Security Engineer. Return ONLY a raw JSON object. "
            "Do not include any preamble, explanation, or markdown code blocks."
        )

        files_section = ""
        for filename, content in files_content.items():
            files_section += f"\n### {filename}\n```\n{content}\n```\n"

        if build_error:
            error_section = (
                f"\nPREVIOUS PATCH ATTEMPT FAILED. The build broke with this error:\n"
                f"```\n{build_error}\n```\n"
                f"You MUST produce a more conservative patch. Prefer the smallest safe version "
                f"upgrade that fixes each vulnerability. Do NOT upgrade dependencies whose new "
                f"version introduces API incompatibilities visible in the error above."
            )
        else:
            error_section = ""

        user_prompt = f"""Fix the following security vulnerabilities in the provided build file(s).

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
"""

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
