from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


class PeerCreate(BaseModel):
    device_name: str | None = Field(
        None, json_schema_extra={"example": "Developer-Laptop"}
    )
    public_key: str | None = Field(
        None, description="Optional. Server auto-creates keys if empty."
    )


class PeerUpdate(BaseModel):
    device_name: str | None = Field(
        None, json_schema_extra={"example": "Developer-Laptop"}
    )
    allowed_ips: str | None = Field(
        None, json_schema_extra={"example": "10.9.0.5/32"}
    )


class PeerResponse(BaseModel):
    id: int
    device_name: str | None
    public_key: str
    private_key: str | None
    allowed_ips: str
    created_at: datetime
    config_file: str

    model_config = ConfigDict(from_attributes=True)
