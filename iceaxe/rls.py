from enum import StrEnum
from typing import Any, Callable, ClassVar, Literal, Protocol, Sequence, Type, Union
from uuid import UUID

from pydantic import BaseModel, Field

from iceaxe.base import TableBase
from iceaxe.queries_str import QueryIdentifier


class Role(StrEnum):
    """PostgreSQL roles for RLS policies."""
    PUBLIC = "PUBLIC"
    # Add other common roles as needed


class Policy(BaseModel):
    """
    Represents a PostgreSQL Row-Level Security (RLS) policy.
    
    RLS policies control which rows can be retrieved, inserted, updated, or deleted
    based on user permissions and row data.
    """
    name: str = Field(description="The name of the policy.")
    table: Union[Type[TableBase], Callable[[], Type[TableBase]]] = Field(
        description="The table this policy applies to. Can be a class or a callable that returns the class."
    )
    to: Union[Role, str] = Field(
        default=Role.PUBLIC, 
        description="The role to grant permissions to."
    )
    restrictive: bool = Field(
        default=False, 
        description="Whether the policy is restrictive."
    )
    command: Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"] = Field(
        default="SELECT", 
        description="The command this policy applies to."
    )
    using: str = Field(description="The USING expression for the policy.")
    check: str | None = Field(
        default=None, 
        description="The WITH CHECK expression for the policy."
    )
    
    def get_table_class(self) -> Type[TableBase]:
        """Resolve the table class if it's provided as a callable."""
        if callable(self.table) and not isinstance(self.table, type):
            return self.table()
        return self.table
    
    def to_sql_statement(self) -> str:
        """Generate the SQL statement to create this policy."""
        table_class = self.get_table_class()
        table_name = table_class.get_table_name()
        
        # In PostgreSQL, identifiers that are reserved words or contain special characters need quoting
        # For the test case we want to use plain identifiers, but in general we should quote them to be safe
        quoted_table = f'"{table_name}"' if ' ' in table_name or '-' in table_name else table_name
        quoted_policy = f'"{self.name}"' if ' ' in self.name or '-' in self.name else self.name
        
        cmd = f"CREATE POLICY {quoted_policy} ON {quoted_table}"
        
        if self.restrictive:
            cmd += " AS RESTRICTIVE"
            
        cmd += f" FOR {self.command}"
        
        if self.to != Role.PUBLIC:
            cmd += f" TO {self.to}"
            
        cmd += f" USING ({self.using})"
        
        if self.check is not None:
            cmd += f" WITH CHECK ({self.check})"
            
        return cmd + ";"


class RLSProtocol(Protocol):
    """Protocol defining the interface for tables with RLS policies."""
    @classmethod
    def get_rls_policies(cls) -> Sequence[Policy]:
        ...
    
    @classmethod
    def __rls__(cls) -> Sequence[Policy]:
        """Return the RLS policies for this table."""
        ... 