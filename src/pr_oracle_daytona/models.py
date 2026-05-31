from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CommandLog(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    step: str
    command: str
    exit_code: int
    output: str
    duration_ms: int
