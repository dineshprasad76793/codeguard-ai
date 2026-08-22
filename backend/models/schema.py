from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    language: str
    code: str


class UrlScanRequest(BaseModel):
    url: str


class AnalyzeResponse(BaseModel):
    success: bool
    analysis: str
