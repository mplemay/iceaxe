from collections.abc import Sequence
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from iceaxe import Field, TableBase


class Role(StrEnum):
    PUBLIC = "PUBLIC"

class Policy(BaseModel):
    name: str = Field(description='The name of the policy.')
    table: TableBase
    to: Role = Field(default=Role.PUBLIC, description="The role to grant permissions to.")
    restrictive: bool = Field(default=False, description="Whether or not the policy is restrictive.")
    command: Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"] = Field(default="SELECT", description="The command the policy applies to.")
    using: Any = Field()
    check: Any



class MyTable(TableBase):
    id: UUID = Field()
    user_id: UUID = Field(foreign_key="user.id")


    def __call__(self) -> Sequence[Any]:
        return [
            Policy(
                name="Owner access.",
                table=self,
                using="user_id = auth.id())",
                check=self.
                
            ),
        ]
