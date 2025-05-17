from pydantic import BaseModel
from typing import Any

class RuntimeEventResponse(BaseModel):
    message: str
    data: Any
