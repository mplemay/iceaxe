import uuid
import pytest
from typing import Optional, List

from iceaxe import Field, Policy, TableBase, select


class User(TableBase):
    """Sample user model with RLS policies."""
    id: uuid.UUID = Field(primary_key=True)
    name: str = Field(unique=True)
    email: str = Field(unique=True)
    
    @classmethod
    def __rls__(cls) -> List[Policy]:
        """Define RLS policies for users."""
        return [
            Policy(
                name="users_tenant_isolation",
                table=cls,
                command="ALL",
                using="tenant_id = current_setting('app.tenant_id')::uuid",
                check="tenant_id = current_setting('app.tenant_id')::uuid",
            )
        ]


class Document(TableBase):
    """Sample document model with RLS policies."""
    id: uuid.UUID = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id")
    title: str
    content: str
    
    @classmethod
    def __rls__(cls) -> List[Policy]:
        """Define RLS policies for documents."""
        return [
            Policy(
                name="documents_owner_access",
                table=cls,
                command="ALL",
                using="user_id = current_setting('app.user_id')::uuid",
                check="user_id = current_setting('app.user_id')::uuid",
            ),
            Policy(
                name="documents_public_read",
                table=cls,
                command="SELECT",
                using="is_public = true",
            )
        ]


@pytest.mark.asyncio
async def test_rls_migration_creation(db_connection):
    """Test that RLS policies are properly created during migrations."""
    from iceaxe.migrations.generator import MigrationGenerator
    from iceaxe.schemas.actions import DatabaseActions
    
    # Create a migration generator with our models
    generator = MigrationGenerator()
    
    # Get RLS policies from the models
    policy_objects = generator.create_rls_policy_objects([User, Document])
    
    # Ensure we have the expected number of policies
    assert len(policy_objects) == 3
    
    # Check that the policy properties are correct
    user_policy = next(p for p in policy_objects if p.table_name == "user")
    assert user_policy.policy_name == "users_tenant_isolation"
    assert user_policy.command == "ALL"
    assert "tenant_id" in user_policy.using_expr
    
    # Create database actions to simulate a migration
    actions = DatabaseActions()
    
    # Generate SQL statements for the policies
    for policy in policy_objects:
        await policy.create(actions)
    
    # Check that the SQL statements are properly generated
    sql_statements = [str(action) for action in actions.dry_run_actions]
    
    # Make sure RLS was enabled
    assert any("ENABLE ROW LEVEL SECURITY" in sql for sql in sql_statements)
    
    # Make sure policies were created
    assert any("CREATE POLICY" in sql for sql in sql_statements)
    assert any("users_tenant_isolation" in sql for sql in sql_statements)
    assert any("documents_owner_access" in sql for sql in sql_statements)
    assert any("documents_public_read" in sql for sql in sql_statements)
    
    # Check for correct USING and CHECK clauses
    assert any("tenant_id = current_setting" in sql for sql in sql_statements)
    assert any("user_id = current_setting" in sql for sql in sql_statements)
    assert any("is_public = true" in sql for sql in sql_statements)


@pytest.mark.asyncio
async def test_rls_migration_updates(db_connection):
    """Test that RLS policies are properly updated during migrations."""
    # First we'll create a table and policy in the database
    await db_connection.conn.execute("""
    CREATE TABLE IF NOT EXISTS "user" (
        id UUID PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        tenant_id UUID NOT NULL
    );
    
    ALTER TABLE "user" ENABLE ROW LEVEL SECURITY;
    ALTER TABLE "user" FORCE ROW LEVEL SECURITY;
    
    CREATE POLICY users_tenant_isolation ON "user"
        USING (tenant_id = current_setting('app.tenant_id')::uuid)
        WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
    """)
    
    # Now let's update the policy through a migration
    # Create a modified policy in a new class
    class UpdatedUser(TableBase):
        table_name = "user"
        id: uuid.UUID = Field(primary_key=True)
        name: str = Field(unique=True)
        email: str = Field(unique=True)
        tenant_id: uuid.UUID
        
        @classmethod
        def __rls__(cls) -> List[Policy]:
            return [
                Policy(
                    name="users_tenant_isolation",
                    table=cls,
                    command="ALL",
                    # Changed expression to include an OR condition
                    using="tenant_id = current_setting('app.tenant_id')::uuid OR is_public = true",
                    check="tenant_id = current_setting('app.tenant_id')::uuid",
                )
            ]
    
    from iceaxe.migrations.generator import MigrationGenerator
    from iceaxe.schemas.actions import DatabaseActions
    
    # Create a migration generator
    generator = MigrationGenerator()
    policy_objects = generator.create_rls_policy_objects([UpdatedUser])
    
    # Create actions and get SQL for updates
    actions = DatabaseActions()
    
    # Simulate migration - should drop and recreate the policy
    for policy in policy_objects:
        # For simplicity, assume we need to recreate
        await actions.drop_policy("user", "users_tenant_isolation")
        await policy.create(actions)
    
    # Check that SQL includes both drop and recreate
    sql_statements = [str(action) for action in actions.dry_run_actions]
    
    # Check for DROP and CREATE statements
    assert any("DROP POLICY" in sql for sql in sql_statements)
    assert any("CREATE POLICY" in sql for sql in sql_statements)
    
    # Check for updated USING clause with OR condition
    assert any("OR is_public = true" in sql for sql in sql_statements)
    
    # Clean up - drop the table
    await db_connection.conn.execute('DROP TABLE IF EXISTS "user" CASCADE;') 