import json
import urllib.error
import urllib.request

from flask import current_app

OPENAI_COMPATIBLE = {
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "openrouter": ("https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct:free"),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
}
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
OLLAMA_DEFAULT_MODEL = "llama3.2"


class AIProviderError(Exception):
    """Raised when the configured LLM cannot be reached or returns an error."""


def provider_status():
    """Describe the active provider for the UI (never includes the key)."""
    config = current_app.config
    name = config["AI_PROVIDER"]
    if name in ("", "none"):
        return {"name": "none", "configured": False, "destination": "none",
                "message": "No LLM configured. Answers come straight from the TRACE X database."}
    if name == "ollama":
        return {"name": name, "configured": True, "destination": "local",
                "model": config["AI_MODEL"] or OLLAMA_DEFAULT_MODEL,
                "message": "Local Ollama model. Case data stays on this computer."}
    if name in OPENAI_COMPATIBLE or name == "gemini":
        has_key = bool(config["AI_API_KEY"])
        model = config["AI_MODEL"] or (GEMINI_DEFAULT_MODEL if name == "gemini" else OPENAI_COMPATIBLE[name][1])
        return {"name": name, "configured": has_key, "destination": "cloud", "model": model,
                "message": (f"Cloud provider '{name}'. Authorised case records for each question are sent to it. "
                            "Use fictional data only.") if has_key else
                           f"AI_PROVIDER is '{name}' but AI_API_KEY is empty."}
    return {"name": name, "configured": False, "destination": "none",
            "message": f"Unknown AI_PROVIDER '{name}'."}


def generate(system_prompt, user_prompt):
    """Send one prompt to the configured LLM and return its text answer."""
    config = current_app.config
    name = config["AI_PROVIDER"]
    status = provider_status()
    if not status["configured"]:
        raise AIProviderError(status["message"])
    if name == "ollama":
        return _ollama(system_prompt, user_prompt, status["model"])
    if name == "gemini":
        return _gemini(system_prompt, user_prompt, status["model"])
    return _openai_compatible(name, system_prompt, user_prompt, status["model"])


def _post_json(url, payload, headers):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=current_app.config["AI_TIMEOUT"]) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        # Read a short part of the provider's error text; it never contains our key.
        detail = error.read().decode("utf-8", errors="replace")[:200]
        raise AIProviderError(f"AI provider returned HTTP {error.code}. {detail}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise AIProviderError(f"AI provider is unreachable ({getattr(error, 'reason', error)}).") from None
    except json.JSONDecodeError:
        raise AIProviderError("AI provider sent a response that is not valid JSON.") from None


def _openai_compatible(name, system_prompt, user_prompt, model):
    base_url = current_app.config["AI_BASE_URL"] or OPENAI_COMPATIBLE[name][0]
    data = _post_json(
        base_url.rstrip("/") + "/chat/completions",
        {"model": model, "temperature": 0.2,
         "messages": [{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]},
        {"Authorization": f"Bearer {current_app.config['AI_API_KEY']}"},
    )
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError):
        raise AIProviderError("Unexpected response format from the AI provider.") from None


def _gemini(system_prompt, user_prompt, model):
    data = _post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        {"systemInstruction": {"parts": [{"text": system_prompt}]},
         "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
         "generationConfig": {"temperature": 0.2}},
        {"x-goog-api-key": current_app.config["AI_API_KEY"]},
    )
    try:
        return "".join(part.get("text", "") for part in data["candidates"][0]["content"]["parts"]).strip()
    except (KeyError, IndexError, TypeError):
        raise AIProviderError("Unexpected response format from Gemini.") from None


def _ollama(system_prompt, user_prompt, model):
    data = _post_json(
        current_app.config["OLLAMA_URL"].rstrip("/") + "/api/chat",
        {"model": model, "stream": False, "options": {"temperature": 0.2,"num_predict": 256},
         "messages": [{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]},
        {},
    )
    try:
        return data["message"]["content"].strip()
    except (KeyError, TypeError):
        raise AIProviderError("Unexpected response format from Ollama.") from None



