"""
Example of using Row Level Security (RLS) with iceaxe.

This example demonstrates a multi-tenant application where:
1. Each user belongs to a tenant
2. Users can only see data from their own tenant
3. Admin users can see all data

To run this example, you need:
- PostgreSQL database
- asyncpg installed
- iceaxe installed
"""

import asyncio
import uuid
from typing import ClassVar, Sequence

import asyncpg

from iceaxe import Field, Policy, Role, TableBase, select
from iceaxe.rls import RLSProtocol
from iceaxe.session import DBConnection


# Define models
class Tenant(TableBase):
    """Tenant model for multi-tenant application."""
    id: uuid.UUID = Field(primary_key=True)
    name: str


class User(TableBase):
    """User model with tenant association."""
    id: uuid.UUID = Field(primary_key=True)
    tenant_id: uuid.UUID = Field(foreign_key="tenant.id")
    username: str = Field(unique=True)
    is_admin: bool = Field(default=False)


class Document(TableBase):
    """Document model with RLS policies."""
    id: uuid.UUID = Field(primary_key=True)
    tenant_id: uuid.UUID = Field(foreign_key="tenant.id")
    title: str
    content: str
    
    # Define RLS policies using the __rls__ method
    @classmethod
    def __rls__(cls) -> Sequence[Policy]:
        return [
            # Admin users can access all documents
            Policy(
                name="admin_access_all",
                table=cls,
                command="ALL",
                using="""
                EXISTS (
                    SELECT 1 FROM "user"
                    WHERE "user".id = current_setting('app.user_id')::uuid
                    AND "user".is_admin = true
                )
                """
            ),
            # Users can only access documents from their own tenant
            Policy(
                name="tenant_users_access",
                table=cls,
                command="ALL",
                using="""
                EXISTS (
                    SELECT 1 FROM "user"
                    WHERE "user".id = current_setting('app.user_id')::uuid
                    AND "user".tenant_id = tenant_id
                )
                """
            )
        ]


async def main():
    """
    Example application flow with RLS.
    
    This simulates:
    1. Creating tenants, users, and documents
    2. Setting up RLS
    3. Testing document access with different user contexts
    """
    # Connect to the database
    conn = await asyncpg.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="postgres",
        database="iceaxe_example"
    )
    
    # Create DB connection
    db = DBConnection(conn)
    
    try:
        # Create tables
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS tenant (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS "user" (
            id UUID PRIMARY KEY,
            tenant_id UUID REFERENCES tenant(id),
            username TEXT UNIQUE NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE
        );
        
        CREATE TABLE IF NOT EXISTS document (
            id UUID PRIMARY KEY,
            tenant_id UUID REFERENCES tenant(id),
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """)
        
        # Create test data
        # Tenants
        tenant1_id = uuid.uuid4()
        tenant2_id = uuid.uuid4()
        
        tenant1 = Tenant(id=tenant1_id, name="Tenant A")
        tenant2 = Tenant(id=tenant2_id, name="Tenant B")
        
        # Users
        admin_id = uuid.uuid4()
        user1_id = uuid.uuid4()
        user2_id = uuid.uuid4()
        
        admin = User(id=admin_id, tenant_id=tenant1_id, username="admin", is_admin=True)
        user1 = User(id=user1_id, tenant_id=tenant1_id, username="user1", is_admin=False)
        user2 = User(id=user2_id, tenant_id=tenant2_id, username="user2", is_admin=False)
        
        # Documents
        doc1 = Document(
            id=uuid.uuid4(),
            tenant_id=tenant1_id,
            title="Tenant A Document",
            content="This belongs to Tenant A"
        )
        
        doc2 = Document(
            id=uuid.uuid4(),
            tenant_id=tenant2_id,
            title="Tenant B Document",
            content="This belongs to Tenant B"
        )
        
        # Insert data
        await db.insert([tenant1, tenant2])
        await db.insert([admin, user1, user2])
        await db.insert([doc1, doc2])
        
        # Enable RLS on document table
        await conn.execute("ALTER TABLE document ENABLE ROW LEVEL SECURITY;")
        await conn.execute("ALTER TABLE document FORCE ROW LEVEL SECURITY;")
        
        # Create policies
        for policy in Document.get_rls_policies():
            await conn.execute(policy.to_sql_statement())
        
        print("\n--- RLS Demonstration ---\n")
        
        # Test with admin user
        print("Testing with admin user:")
        with db.rls_context(**{'app.user_id': str(admin_id)}):
            docs = await db.exec(select(Document))
            print(f"  Admin can see {len(docs)} documents:")
            for doc in docs:
                print(f"  - {doc.title}")
        
        # Test with Tenant A user
        print("\nTesting with Tenant A user:")
        with db.rls_context(**{'app.user_id': str(user1_id)}):
            docs = await db.exec(select(Document))
            print(f"  Tenant A user can see {len(docs)} documents:")
            for doc in docs:
                print(f"  - {doc.title}")
        
        # Test with Tenant B user
        print("\nTesting with Tenant B user:")
        with db.rls_context(**{'app.user_id': str(user2_id)}):
            docs = await db.exec(select(Document))
            print(f"  Tenant B user can see {len(docs)} documents:")
            for doc in docs:
                print(f"  - {doc.title}")
        
    finally:
        # Clean up
        await conn.execute("DROP TABLE IF EXISTS document;")
        await conn.execute("DROP TABLE IF EXISTS \"user\";")
        await conn.execute("DROP TABLE IF EXISTS tenant;")
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main()) 