import os
import json
from google import genai
from google.genai import types
import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

# Setup a local, no-infra metric reader
reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
provider = MeterProvider(metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter("remediation.agent")

# Define Metrics
latency_hist = meter.create_histogram("llm_latency", unit="ms")
token_counter = meter.create_counter("llm_tokens_total")


# Initialize OTel Metrics
meter = metrics.get_meter("security.agent")
latency_histogram = meter.create_histogram("llm_inference_latency", unit="ms")
token_counter = meter.create_counter("llm_tokens_total")

class SecurityAgentClient:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("❌ GEMINI_API_KEY not found in environment.")
        
        self.client = genai.Client(api_key=api_key)
        # Use the verified active model from your list
        self.model_id = "gemini-2.5-flash" 

    def get_remediation_plan(self, ghsa_ids, pom_content, build_error=None):
        start = time.time()
        system_instructions = (
            "You are a Senior Security Engineer. Return ONLY a raw JSON object. "
            "Do not include any preamble or markdown blocks."
        )

        user_prompt = f"""
        Fix GHSAs: {ghsa_ids}
        POM: {pom_content}
        Error: {build_error if build_error else "None"}
        
        Format:
        {{
            "target_version": "string",
            "parent_version": "string",
            "analysis": "string"
        }}
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
            
            # FIXED: Robust JSON extraction logic
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
            print(f"❌ LLM Inference Error: {e}")
            return None