from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class AnalysisOptions(BaseModel):
    """Strict whitelist for analysis toggles. Unknown keys are rejected
    with a 422, preventing option/parameter pollution."""

    model_config = ConfigDict(extra="forbid")

    owasp: bool = False
    secrets: bool = False
    deps: bool = False


class AnalyzeRequest(BaseModel):
    language: str = Field(min_length=1, max_length=40)
    code: str = Field(min_length=0, max_length=150_000)
    options: Optional[AnalysisOptions] = None
    custom_rules: Optional[List[str]] = None
    stream: bool = False


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    stream: bool = False


class GithubScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=500)
    options: Optional[AnalysisOptions] = None
    custom_rules: Optional[List[str]] = None
    stream: bool = False


class AnalyzeResponse(BaseModel):
    success: bool
    analysis: str
