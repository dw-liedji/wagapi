import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {
        "env_file": os.environ.get("WAGAPI_ENV_FILE", ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    wagapi_api_key: str = "ProductionSecretDynamicTunnelAPIKeyCredentialToken"
    wagapi_data_dir: str = "data"

    wg0_private_key: str = ""
    wg0_public_key: str = "wg0_public_key_placeholder"
    wg0_endpoint: str = "vpn.example.com:51820"
    wg0_dns: str = "1.1.1.1"
    wg0_listen_port: int = 51820

    subnet_pool: str = "10.9.0.0/16"


settings = Settings()
