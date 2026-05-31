from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


class InterfaceCreate(BaseModel):
    name: str = Field(
        ...,
        json_schema_extra={"example": "wg1"},
        description="Link identifier. Cannot be 'wg0'",
    )
    subnet_pool: str = Field(
        "10.9.0.0/16", json_schema_extra={"example": "10.9.0.0/16"}
    )
    listen_port: int = Field(
        ...,
        json_schema_extra={"example": 51821},
        description="Must not conflict with port 51820",
    )
    endpoint: str = Field(
        ..., json_schema_extra={"example": "vpn.yourcompany.com:51821"}
    )
    dns: str = Field("1.1.1.1", json_schema_extra={"example": "1.1.1.1"})


class InterfaceResponse(BaseModel):
    id: int
    name: str
    subnet_pool: str
    listen_port: int
    public_key: str
    endpoint: str
    dns: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PeerCreate(BaseModel):
    device_name: str | None = Field(
        None, json_schema_extra={"example": "Developer-Laptop"}
    )
    public_key: str | None = Field(
        None, description="Optional. Server auto-creates keys if empty."
    )


class InterfaceUpdate(BaseModel):
    subnet_pool: str | None = None
    listen_port: int | None = Field(
        None, json_schema_extra={"example": 51821}
    )
    endpoint: str | None = Field(
        None, json_schema_extra={"example": "vpn.yourcompany.com:51821"}
    )
    dns: str | None = Field(None, json_schema_extra={"example": "1.1.1.1"})


class PeerUpdate(BaseModel):
    device_name: str | None = Field(
        None, json_schema_extra={"example": "Developer-Laptop"}
    )
    allowed_ips: str | None = Field(
        None, json_schema_extra={"example": "10.9.0.5/32"}
    )


class PeerResponse(BaseModel):
    id: int
    interface_id: int
    device_name: str | None
    public_key: str
    private_key: str | None
    allowed_ips: str
    created_at: datetime
    config_file: str

    model_config = ConfigDict(from_attributes=True)
