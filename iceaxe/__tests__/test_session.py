import pytest

from iceaxe.__tests__.conf_models import ArtifactDemo, UserDemo
from iceaxe.functions import func
from iceaxe.queries import JoinType, OrderDirection, QueryBuilder
from iceaxe.session import (
    DBConnection,
)
from iceaxe.typing import col

#
# Insert / Update with ORM objects
#


@pytest.mark.asyncio
async def test_db_connection_insert(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])

    result = await db_connection.conn.fetch(
        "SELECT * FROM userdemo WHERE name = $1", "John Doe"
    )
    assert len(result) == 1
    assert result[0]["id"] == user.id
    assert result[0]["name"] == "John Doe"
    assert result[0]["email"] == "john@example.com"
    assert user.get_modified_attributes() == {}


@pytest.mark.asyncio
async def test_db_connection_update(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])

    user.name = "Jane Doe"
    await db_connection.update([user])

    result = await db_connection.conn.fetch(
        "SELECT * FROM userdemo WHERE id = $1", user.id
    )
    assert len(result) == 1
    assert result[0]["name"] == "Jane Doe"
    assert user.get_modified_attributes() == {}


@pytest.mark.asyncio
async def test_db_obj_mixin_track_modifications():
    user = UserDemo(name="John Doe", email="john@example.com")
    assert user.get_modified_attributes() == {}

    user.name = "Jane Doe"
    assert user.get_modified_attributes() == {"name": "Jane Doe"}

    user.email = "jane@example.com"
    assert user.get_modified_attributes() == {
        "name": "Jane Doe",
        "email": "jane@example.com",
    }

    user.clear_modified_attributes()
    assert user.get_modified_attributes() == {}


@pytest.mark.asyncio
async def test_db_connection_insert_multiple(db_connection: DBConnection):
    userdemo = [
        UserDemo(name="John Doe", email="john@example.com"),
        UserDemo(name="Jane Doe", email="jane@example.com"),
    ]

    await db_connection.insert(userdemo)

    result = await db_connection.conn.fetch("SELECT * FROM userdemo ORDER BY id")
    assert len(result) == 2
    assert result[0]["name"] == "John Doe"
    assert result[1]["name"] == "Jane Doe"
    assert userdemo[0].id == result[0]["id"]
    assert userdemo[1].id == result[1]["id"]
    assert all(user.get_modified_attributes() == {} for user in userdemo)


@pytest.mark.asyncio
async def test_db_connection_update_multiple(db_connection: DBConnection):
    userdemo = [
        UserDemo(name="John Doe", email="john@example.com"),
        UserDemo(name="Jane Doe", email="jane@example.com"),
    ]
    await db_connection.insert(userdemo)

    userdemo[0].name = "Johnny Doe"
    userdemo[1].email = "janey@example.com"

    await db_connection.update(userdemo)

    result = await db_connection.conn.fetch("SELECT * FROM userdemo ORDER BY id")
    assert len(result) == 2
    assert result[0]["name"] == "Johnny Doe"
    assert result[1]["email"] == "janey@example.com"
    assert all(user.get_modified_attributes() == {} for user in userdemo)


@pytest.mark.asyncio
async def test_db_connection_insert_empty_list(db_connection: DBConnection):
    await db_connection.insert([])
    result = await db_connection.conn.fetch("SELECT * FROM userdemo")
    assert len(result) == 0


@pytest.mark.asyncio
async def test_db_connection_update_empty_list(db_connection: DBConnection):
    await db_connection.update([])
    # This test doesn't really assert anything, as an empty update shouldn't change the database


@pytest.mark.asyncio
async def test_db_connection_update_no_modifications(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])

    await db_connection.update([user])

    result = await db_connection.conn.fetch(
        "SELECT * FROM userdemo WHERE id = $1", user.id
    )
    assert len(result) == 1
    assert result[0]["name"] == "John Doe"
    assert result[0]["email"] == "john@example.com"


#
# Select into ORM objects
#


@pytest.mark.asyncio
async def test_select(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])

    # Table selection
    result_1 = await db_connection.exec(QueryBuilder().select(UserDemo))
    assert result_1 == [UserDemo(id=user.id, name="John Doe", email="john@example.com")]

    # Single column selection
    result_2 = await db_connection.exec(QueryBuilder().select(UserDemo.email))
    assert result_2 == ["john@example.com"]

    # Multiple column selection
    result_3 = await db_connection.exec(
        QueryBuilder().select((UserDemo.name, UserDemo.email))
    )
    assert result_3 == [("John Doe", "john@example.com")]

    # Table and column selection
    result_4 = await db_connection.exec(
        QueryBuilder().select((UserDemo, UserDemo.email))
    )
    assert result_4 == [
        (
            UserDemo(id=user.id, name="John Doe", email="john@example.com"),
            "john@example.com",
        )
    ]


@pytest.mark.asyncio
async def test_select_where(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])

    new_query = QueryBuilder().select(UserDemo).where(UserDemo.name == "John Doe")
    result = await db_connection.exec(new_query)
    assert result == [
        UserDemo(id=user.id, name="John Doe", email="john@example.com"),
    ]


@pytest.mark.asyncio
async def test_select_join(db_connection: DBConnection):
    user = UserDemo(name="John Doe", email="john@example.com")
    await db_connection.insert([user])
    assert user.id is not None

    artifact = ArtifactDemo(title="Artifact 1", user_id=user.id)
    await db_connection.insert([artifact])

    new_query = (
        QueryBuilder()
        .select((ArtifactDemo, UserDemo.email))
        .join(UserDemo, UserDemo.id == ArtifactDemo.user_id)
        .where(UserDemo.name == "John Doe")
    )
    result = await db_connection.exec(new_query)
    assert result == [
        (
            ArtifactDemo(id=artifact.id, title="Artifact 1", user_id=user.id),
            "john@example.com",
        )
    ]


@pytest.mark.asyncio
async def test_select_with_limit_and_offset(db_connection: DBConnection):
    users = [
        UserDemo(name="User 1", email="user1@example.com"),
        UserDemo(name="User 2", email="user2@example.com"),
        UserDemo(name="User 3", email="user3@example.com"),
        UserDemo(name="User 4", email="user4@example.com"),
        UserDemo(name="User 5", email="user5@example.com"),
    ]
    await db_connection.insert(users)

    query = (
        QueryBuilder()
        .select(UserDemo)
        .order_by(UserDemo.id, OrderDirection.ASC)
        .limit(2)
        .offset(1)
    )
    result = await db_connection.exec(query)
    assert len(result) == 2
    assert result[0].name == "User 2"
    assert result[1].name == "User 3"


@pytest.mark.asyncio
async def test_select_with_multiple_where_conditions(db_connection: DBConnection):
    users = [
        UserDemo(name="John Doe", email="john@example.com"),
        UserDemo(name="Jane Doe", email="jane@example.com"),
        UserDemo(name="Bob Smith", email="bob@example.com"),
    ]
    await db_connection.insert(users)

    query = (
        QueryBuilder()
        .select(UserDemo)
        .where(col(UserDemo.name).like("%Doe%"), UserDemo.email != "john@example.com")
    )
    result = await db_connection.exec(query)
    assert len(result) == 1
    assert result[0].name == "Jane Doe"


@pytest.mark.asyncio
async def test_select_with_order_by_multiple_columns(db_connection: DBConnection):
    users = [
        UserDemo(name="Alice", email="alice@example.com"),
        UserDemo(name="Bob", email="bob@example.com"),
        UserDemo(name="Charlie", email="charlie@example.com"),
        UserDemo(name="Alice", email="alice2@example.com"),
    ]
    await db_connection.insert(users)

    query = (
        QueryBuilder()
        .select(UserDemo)
        .order_by(UserDemo.name, OrderDirection.ASC)
        .order_by(UserDemo.email, OrderDirection.ASC)
    )
    result = await db_connection.exec(query)
    assert len(result) == 4
    assert result[0].name == "Alice" and result[0].email == "alice2@example.com"
    assert result[1].name == "Alice" and result[1].email == "alice@example.com"
    assert result[2].name == "Bob"
    assert result[3].name == "Charlie"


@pytest.mark.asyncio
async def test_select_with_group_by_and_having(db_connection: DBConnection):
    users = [
        UserDemo(name="John", email="john@example.com"),
        UserDemo(name="Jane", email="jane@example.com"),
        UserDemo(name="John", email="john2@example.com"),
        UserDemo(name="Bob", email="bob@example.com"),
    ]
    await db_connection.insert(users)

    query = (
        QueryBuilder()
        .select((UserDemo.name, func.count(UserDemo.id)))
        .group_by(UserDemo.name)
        .having(func.count(UserDemo.id) > 1)
    )
    result = await db_connection.exec(query)
    assert len(result) == 1
    assert result[0] == ("John", 2)


@pytest.mark.asyncio
async def test_select_with_left_join(db_connection: DBConnection):
    users = [
        UserDemo(name="John", email="john@example.com"),
        UserDemo(name="Jane", email="jane@example.com"),
    ]
    await db_connection.insert(users)

    posts = [
        ArtifactDemo(title="John's Post", user_id=users[0].id),
        ArtifactDemo(title="Another Post", user_id=users[0].id),
    ]
    await db_connection.insert(posts)

    query = (
        QueryBuilder()
        .select((UserDemo.name, func.count(ArtifactDemo.id)))
        .join(ArtifactDemo, UserDemo.id == ArtifactDemo.user_id, JoinType.LEFT)
        .group_by(UserDemo.name)
        .order_by(UserDemo.name, OrderDirection.ASC)
    )
    result = await db_connection.exec(query)
    assert len(result) == 2
    assert result[0] == ("Jane", 0)
    assert result[1] == ("John", 2)


# @pytest.mark.asyncio
# async def test_select_with_subquery(db_connection: DBConnection):
#     users = [
#         UserDemo(name="John", email="john@example.com"),
#         UserDemo(name="Jane", email="jane@example.com"),
#         UserDemo(name="Bob", email="bob@example.com"),
#     ]
#     await db_connection.insert(users)

#     posts = [
#         ArtifactDemo(title="John's Post", content="Hello", user_id=users[0].id),
#         ArtifactDemo(title="Jane's Post", content="World", user_id=users[1].id),
#         ArtifactDemo(title="John's Second Post", content="!", user_id=users[0].id),
#     ]
#     await db_connection.insert(posts)

#     subquery = QueryBuilder().select(ArtifactDemo.user_id).where(func.count(ArtifactDemo.id) > 1).group_by(PostDemo.user_id)
#     query = QueryBuilder().select(UserDemo).where(is_column(UserDemo.id).in_(subquery))
#     result = await db_connection.exec(query)
#     assert len(result) == 1
#     assert result[0].name == "John"


@pytest.mark.asyncio
async def test_select_with_distinct(db_connection: DBConnection):
    users = [
        UserDemo(name="John", email="john@example.com"),
        UserDemo(name="Jane", email="jane@example.com"),
        UserDemo(name="John", email="john2@example.com"),
    ]
    await db_connection.insert(users)

    query = (
        QueryBuilder()
        .select(func.distinct(UserDemo.name))
        .order_by(UserDemo.name, OrderDirection.ASC)
    )
    result = await db_connection.exec(query)
    assert result == ["Jane", "John"]
