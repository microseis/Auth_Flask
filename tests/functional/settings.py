from pydantic import BaseSettings


class TestSettings(BaseSettings):
    redis_host: str
    redis_port: str

    class Config:
        env_file = ".env"


test_settings = TestSettings()
