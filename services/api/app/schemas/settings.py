from pydantic import BaseModel


class SettingsUpdate(BaseModel):
    settings: dict[str, str]
