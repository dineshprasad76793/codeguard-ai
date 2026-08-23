from typing import Optional, List
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    language: str
    code: str
    options: Optional[dict] = None
    custom_rules: Optional[List[str]] = None
    stream: bool = False


class UrlScanRequest(BaseModel):
    url: str
    stream: bool = False


class GithubScanRequest(BaseModel):
    url: str
    options: Optional[dict] = None
    custom_rules: Optional[List[str]] = None
    stream: bool = False


class AnalyzeResponse(BaseModel):
    success: bool
    analysis: str
