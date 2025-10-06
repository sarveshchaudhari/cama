from __future__ import annotations

from typing import List, Dict, Any

from crewai.tools import BaseTool

try:
    # Prefer duckduckgo_search if available
    from duckduckgo_search import DDGS  # type: ignore
except Exception:  # pragma: no cover
    DDGS = None  # type: ignore
    import requests  # type: ignore
    from urllib.parse import quote_plus  # type: ignore


class DuckDuckGoSearchTool(BaseTool):
    """Search the web using DuckDuckGo and return top results.

    Input: a string query. Optional limit can be appended like '::5'.
    Output: JSON string with a list of {title, href, snippet}.
    """

    name: str = "duckduckgo_search_tool"
    description: str = (
        "Search the web for security threats, vulnerabilities, and compliance references using DuckDuckGo. "
        "Append '::N' to limit results (default 5)."
    )

    def _run(self, query: str) -> str:  # type: ignore[override]
        limit = 5
        if "::" in query:
            q, lim = query.rsplit("::", 1)
            query = q.strip()
            try:
                limit = max(1, min(10, int(lim.strip())))
            except Exception:
                limit = 5
        results: List[Dict[str, Any]] = []
        try:
            if DDGS is not None:
                with DDGS() as ddgs:  # type: ignore
                    for r in ddgs.text(query, max_results=limit):  # type: ignore
                        results.append({
                            "title": r.get("title"),
                            "href": r.get("href"),
                            "snippet": r.get("body") or r.get("snippet"),
                        })
            else:
                # Fallback: simple HTML search page parse (best-effort)
                url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
                resp = requests.get(url, timeout=15)
                if resp.ok:
                    # crude extraction
                    for line in resp.text.splitlines():
                        if '<a rel="nofollow" class="result__a"' in line:
                            # very rough parse
                            title = line.split('>')[1].split('<')[0]
                            href = line.split('href="')[1].split('"')[0]
                            results.append({"title": title, "href": href, "snippet": ""})
                            if len(results) >= limit:
                                break
        except Exception:
            pass
        return __import__("json").dumps(results, ensure_ascii=False)

