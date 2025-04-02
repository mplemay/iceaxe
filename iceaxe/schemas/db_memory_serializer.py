from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from inspect import isgenerator
from typing import Any, Generator, Sequence, Type, TypeVar, Union
from uuid import UUID

from pydantic_core import PydanticUndefined

from iceaxe.base import (
    DBFieldInfo,
    IndexConstraint,
    TableBase,
    UniqueConstraint,
)
from iceaxe.generics import (
    get_typevar_mapping,
    has_null_type,
    is_type_compatible,
    remove_null_type,
)
from iceaxe.migrations.action_sorter import ActionTopologicalSorter
from iceaxe.postgres import (
    PostgresDateTime,
    PostgresForeignKey,
    PostgresTime,
)
from iceaxe.rls import RLSProtocol
from iceaxe.schemas.actions import (
    CheckConstraint,
    ColumnType,
    ConstraintType,
    DatabaseActions,
    ForeignKeyConstraint,
)
from iceaxe.schemas.db_stubs import (
    DBColumn,
    DBColumnPointer,
    DBConstraint,
    DBConstraintPointer,
    DBObject,
    DBObjectPointer,
    DBPointerOr,
    DBPolicy,
    DBTable,
    DBType,
    DBTypePointer,
)
from iceaxe.sql_types import enum_to_name
from iceaxe.typing import (
    ALL_ENUM_TYPES,
    DATE_TYPES,
    JSON_WRAPPER_FALLBACK,
    PRIMITIVE_WRAPPER_TYPES,
)

NodeYieldType = Union[DBObject, DBObjectPointer, "NodeDefinition"]


@dataclass
class NodeDefinition:
    node: DBObject
    dependencies: list[DBObject | DBObjectPointer]
    force_no_dependencies: bool


class DatabaseMemorySerializer:
    """
    Serialize the in-memory database representations into a format that can be
    compared to the database definitions on disk.

    """

    def __init__(self):
        # Construct the directed acyclic graph of the in-memory database objects
        # that indicate what order items should be fulfilled in
        self.db_dag = []

        self.database_handler = DatabaseHandler()

    def delegate(self, tables: list[Type[TableBase]]):
        """
        Find the most specific relevant handler. For instance, if a subclass
        is a registered handler, we should use that instead of the superclass
        If multiple are found we throw, since we can't determine which one to use
        for the resolution.

        """
        yield from self.database_handler.convert(tables)

    def order_db_objects(
        self,
        db_objects: Sequence[tuple[DBObject, Sequence[DBObject | DBObjectPointer]]],
    ):
        """
        Resolve the order that the database objects should be created or modified
        by normalizing pointers/full objects and performing a sort of their defined
        DAG dependencies in the migration graph.

        """
        # First, go through and create a representative object for each of
        # the representation names
        db_objects_by_name: dict[str, DBObject] = {}
        for db_object, _ in db_objects:
            # Only perform this mapping for objects that are not pointers
            if isinstance(db_object, DBObjectPointer):
                continue

            # If the object is already in the dictionary, try to merge the two
            # different values. Otherwise this indicates that there is a conflicting
            # name with a different definition which we don't allow
            if db_object.representation() in db_objects_by_name:
                current_obj = db_objects_by_name[db_object.representation()]
                db_objects_by_name[db_object.representation()] = current_obj.merge(
                    db_object
                )
            else:
                db_objects_by_name[db_object.representation()] = db_object

        # Make sure all the pointers can be resolved by full objects
        # Otherwise we want a verbose error that gives more context
        for _, dependencies in db_objects:
            for dep in dependencies:
                if isinstance(dep, DBObjectPointer):
                    if isinstance(dep, DBPointerOr):
                        # For OR pointers, at least one of the pointers must be resolvable
                        if not any(
                            pointer.representation() in db_objects_by_name
                            for pointer in dep.pointers
                        ):
                            raise ValueError(
                                f"None of the OR pointers {[p.representation() for p in dep.pointers]} found in the defined database objects"
                            )
                    elif dep.representation() not in db_objects_by_name:
                        raise ValueError(
                            f"Pointer {dep.representation()} not found in the defined database objects"
                        )

        # Map the potentially different objects to the same object
        graph_edges = {}
        for obj, dependencies in db_objects:
            resolved_deps = []
            for dep in dependencies:
                if isinstance(dep, DBObjectPointer):
                    if isinstance(dep, DBPointerOr):
                        # Add all resolvable pointers as dependencies
                        resolved_deps.extend(
                            db_objects_by_name[pointer.representation()]
                            for pointer in dep.pointers
                            if pointer.representation() in db_objects_by_name
                        )
                    else:
                        resolved_deps.append(db_objects_by_name[dep.representation()])
                else:
                    resolved_deps.append(dep)

            if isinstance(obj, DBObjectPointer):
                continue

            graph_edges[db_objects_by_name[obj.representation()]] = resolved_deps

        # Construct the directed acyclic graph
        ts = ActionTopologicalSorter(graph_edges)
        return {obj: i for i, obj in enumerate(ts.sort())}

    async def build_actions(
        self,
        actor: DatabaseActions,
        previous: list[DBObject],
        previous_ordering: dict[DBObject, int],
        next: list[DBObject],
        next_ordering: dict[DBObject, int],
    ):
        # Arrange each object by their representation so we can determine
        # the state of each
        previous_by_name = {obj.representation(): obj for obj in previous}
        next_by_name = {obj.representation(): obj for obj in next}

        previous_ordering_by_name = {
            obj.representation(): order for obj, order in previous_ordering.items()
        }
        next_ordering_by_name = {
            obj.representation(): order for obj, order in next_ordering.items()
        }

        # Verification that the ordering dictionaries align with the objects
        for ordering, objects in [
            (previous_ordering_by_name, previous_by_name),
            (next_ordering_by_name, next_by_name),
        ]:
            if set(ordering.keys()) != set(objects.keys()):
                unique_keys = (set(ordering.keys()) - set(objects.keys())) | (
                    set(objects.keys()) - set(ordering.keys())
                )
                raise ValueError(
                    f"Ordering dictionary keys must be the same as the objects in the list: {unique_keys}"
                )

        # Sort the objects by the order that they should be created in. Only create one object
        # for each representation value, in case we were passed duplicate objects.
        previous = sorted(
            previous_by_name.values(),
            key=lambda obj: previous_ordering_by_name[obj.representation()],
        )
        next = sorted(
            next_by_name.values(),
            key=lambda obj: next_ordering_by_name[obj.representation()],
        )

        # Get the set of objects by representation that exist in the previous and next generations
        previous_reps = {obj.representation() for obj in previous}
        next_reps = {obj.representation() for obj in next}

        # To be created are objects that don't exist in the previous one but exist in the next
        # To be destroyed are objects that exist in the previous one but don't exist in the next
        # To be updated are objects that exist in both the prev and next and have different values

        for obj in previous:
            if obj.representation() not in next_reps:
                actor.add_comment(f"DESTROY {obj.representation()}")
                await obj.destroy(actor)

        for obj in next:
            if obj.representation() not in previous_reps:
                actor.add_comment(f"CREATE {obj.representation()}")
                await obj.create(actor)
            else:
                # This obj exists in both previous and next
                previous_obj = previous_by_name[obj.representation()]
                if previous_obj != obj:
                    actor.add_comment(f"MIGRATE {obj.representation()}")
                    await obj.migrate(previous_obj, actor)


class TypeDeclarationResponse(DBObject):
    # Not really a db object, but we need to fulfill the yield contract
    # They'll be filtered out later
    primitive_type: ColumnType | None = None
    custom_type: DBType | None = None
    is_list: bool = False

    def representation(self) -> str:
        raise NotImplementedError

    async def create(self, actor: DatabaseActions):
        raise NotImplementedError

    async def destroy(self, actor: DatabaseActions):
        raise NotImplementedError

    async def migrate(self, previous, actor: DatabaseActions):
        raise NotImplementedError


class DatabaseHandler:
    def __init__(self):
        # Empty init for now - we could add more handlers in the future, registering subclasses
        # for more operations.
        pass

    def convert(self, tables: list[Type[TableBase]]):
        for table in tables:
            yield from self.convert_table(table)

    def convert_table(self, table: Type[TableBase]):
        # Handle the table itself
        table_name = table.get_table_name()
        table_obj = DBTable(table_name=table_name)
        dependencies = []
        yield table_obj, dependencies

        # Handle the columns
        primary_keys = []
        for key, info in table.model_fields.items():
            if not hasattr(info, "db_field_info"):
                # If this is a normal field (not a DBField), we can't migrate it
                continue

            field_info = info.db_field_info

            # Save information to detect if this is a primary key
            # That's stored as a constraint, not a column property
            if field_info.primary_key:
                primary_keys.append((key, field_info))

            yield from self.convert_column(key, field_info, table)

        # Handle the constraints that are applied to the table via TableBase.model_fields
        for key, info in table.model_fields.items():
            if not hasattr(info, "db_field_info"):
                # If this is a normal field (not a DBField), we can't migrate it
                continue

            field_info = info.db_field_info
            yield from self.handle_single_constraints(key, field_info, table)

        # If there are primary keys, we need to register those as a constraint
        if primary_keys:
            yield from self.handle_primary_keys(primary_keys, table)

        # Handle any constraints on the table
        if hasattr(table, "table_args") and table.table_args != PydanticUndefined and table.table_args is not None:
            for constraint in table.table_args:
                yield from self.handle_multiple_constraints(constraint, table)

        # Handle RLS policies
        if hasattr(table, "get_rls_policies") and callable(table.get_rls_policies):
            policies = table.get_rls_policies()
            if policies:
                # First enable RLS on the table
                yield DBRLSEnabled(table_name=table_name, force=True), [table_obj]
                
                # Then add each policy
                for policy in policies:
                    policy_obj = DBPolicy(
                        policy_name=policy.name,
                        table_name=table_name,
                        restrictive=policy.restrictive,
                        command=policy.command,
                        role="",  # Default empty role means policy applies to all roles
                        using_expr=policy.using,
                        check_expr=policy.check if policy.command != "SELECT" else None,
                    )
                    yield policy_obj, [table_obj]

    def convert_column(self, key: str, info: DBFieldInfo, table: Type[TableBase]):
        # Types must be created first, before columns that refer to them
        yield from self.handle_column_type(key, info, table)

        column_type, is_list = self._get_type_declaration(info)
        table_name = table.get_table_name()

        # Create a column
        column = DBColumn(
            table_name=table_name,
            column_name=key,
            column_type=column_type,
            column_is_list=is_list,
            nullable=info.nullable and not info.primary_key,
            autoincrement=info.autoincrement,
        )

        # Save a pointer to the table for use in dependencies
        table_ptr = DBTable(table_name=table_name)

        yield column, [table_ptr]

    def _get_type_declaration(self, info: DBFieldInfo):
        """
        Determine the final column type and whether it's a list. This can be
        used by both column creation and constraint creation.

        :param info: The field info containing SQL type information.
        :return: A tuple of (column_type_pointer_or_enum, is_list)
        """
        is_list = False
        column_type = None

        if (hasattr(info.annotation, "__origin__") and 
            info.annotation.__origin__ is list and 
            hasattr(info.annotation, "__args__")):
            # This is a list type, so we need to get the inner type
            is_list = True
            inner_type = info.annotation.__args__[0]

            # Check if the list contains an enum type
            if isinstance(inner_type, type) and issubclass(inner_type, ALL_ENUM_TYPES):
                column_type = DBTypePointer(name=enum_to_name(inner_type))
            elif not isinstance(inner_type, type) and hasattr(inner_type, "__members__"):
                column_type = DBTypePointer(name=enum_to_name(inner_type))
            else:
                is_primitive = inner_type in PRIMITIVE_WRAPPER_TYPES
                is_date = inner_type in DATE_TYPES
                if is_primitive or is_date:
                    # Convert Python types to Postgres types
                    type_name = info.get_column_type()
                    column_type = ColumnType(type_name)
                else:
                    # For non-primitives, we assume JSON serialization
                    column_type = ColumnType("jsonb")
        else:
            # Handle enums specially
            if isinstance(info.annotation, type) and issubclass(info.annotation, ALL_ENUM_TYPES):
                column_type = DBTypePointer(name=enum_to_name(info.annotation))
            elif not isinstance(info.annotation, type) and hasattr(info.annotation, "__members__"):
                column_type = DBTypePointer(name=enum_to_name(info.annotation))
            else:
                # TODO: Handle generic types, custom classes for JSON, ForeignKeys
                type_name = info.get_column_type()
                column_type = ColumnType(type_name)

        return column_type, is_list

    def handle_column_type(self, key: str, info: DBFieldInfo, table: Type[TableBase]):
        if (hasattr(info.annotation, "__origin__") and 
            info.annotation.__origin__ is list and 
            hasattr(info.annotation, "__args__")):
            # For lists, we need to handle the internal type
            inner_type = info.annotation.__args__[0]

            if isinstance(inner_type, type) and issubclass(inner_type, ALL_ENUM_TYPES):
                values = [str(value.value) for value in inner_type]
                name = enum_to_name(inner_type)
                
                db_type = DBType(
                    name=name, 
                    values=frozenset(values), 
                    reference_columns=frozenset([(table.get_table_name(), key)])
                )
                yield db_type, []
                return

        if isinstance(info.annotation, type) and issubclass(info.annotation, ALL_ENUM_TYPES):
            values = [str(value.value) for value in info.annotation]
            name = enum_to_name(info.annotation)

            db_type = DBType(
                name=name, 
                values=frozenset(values),
                reference_columns=frozenset([(table.get_table_name(), key)])
            )
            yield db_type, []
            return

    def handle_single_constraints(
        self, key: str, info: DBFieldInfo, table: Type[TableBase]
    ):
        def _build_constraint(
            constraint_type: ConstraintType,
            *,
            foreign_key_constraint: ForeignKeyConstraint | None = None,
            check_constraint: CheckConstraint | None = None,
        ):
            # Unique and primary keys are specified elsewhere; this is handled specially
            # for cases where we have 1 column unique constraints or primary keys
            table_name = table.get_table_name()
            constraint_name = DBConstraint.new_constraint_name(
                table_name=table_name,
                columns=[key],
                constraint_type=constraint_type,
            )

            return DBConstraint(
                table_name=table_name,
                constraint_name=constraint_name,
                columns=frozenset([key]),
                constraint_type=constraint_type,
                foreign_key_constraint=foreign_key_constraint,
                check_constraint=check_constraint,
            )

        table_name = table.get_table_name()
        # Save pointers for use in dependencies
        table_ptr = DBTable(table_name=table_name)
        column_ptr = DBColumnPointer(table_name=table_name, column_name=key)

        # Constraints for this column
        if info.unique and not info.primary_key:
            # Should only specify one of unique OR primary key - unique is implied by pk
            constraint = _build_constraint(
                constraint_type=ConstraintType.UNIQUE,
            )
            yield constraint, [table_ptr, column_ptr]

        if info.foreign_key:
            parts = info.foreign_key.split(".")
            if len(parts) != 2:
                raise ValueError(
                    f"Foreign key {info.foreign_key!r} is improperly"
                    "formatted; expected [TABLE].[COLUMN]"
                )

            ref_table, ref_col = parts
            constraint = _build_constraint(
                constraint_type=ConstraintType.FOREIGN_KEY,
                foreign_key_constraint=ForeignKeyConstraint(
                    target_table=ref_table,
                    target_columns=frozenset([ref_col]),
                    on_delete=info.on_delete,
                    on_update=info.on_update,
                ),
            )

            # For FKs, we have a reference to the target table, not the source table
            dst_table_ptr = DBTable(table_name=ref_table)
            dst_column_ptr = DBColumnPointer(table_name=ref_table, column_name=ref_col)

            yield constraint, [
                table_ptr,
                column_ptr,
                dst_table_ptr,
                dst_column_ptr,
            ]

        if info.check_fn:
            condition = info.check_fn.__doc__
            if not condition:
                raise ValueError(
                    f"Check function {info.check_fn.__name__} missing docstring with SQL condition"
                )

            constraint = _build_constraint(
                constraint_type=ConstraintType.CHECK,
                check_constraint=CheckConstraint(check_condition=condition),
            )
            yield constraint, [table_ptr, column_ptr]

    def handle_multiple_constraints(
        self, constraint: UniqueConstraint | IndexConstraint, table: Type[TableBase]
    ):
        table_name = table.get_table_name()
        # Save a pointer to the table for use in dependencies
        table_ptr = DBTable(table_name=table_name)

        if isinstance(constraint, UniqueConstraint):
            if not constraint.columns:
                raise ValueError("UniqueConstraint must specify at least 1 columns")

            # Create the constraint directly
            for i, column in enumerate(constraint.columns):
                # Create a pointer to each column
                yield DBColumnPointer(table_name=table_name, column_name=column), []

            constraint_name = DBConstraint.new_constraint_name(
                table_name=table_name,
                columns=constraint.columns,
                constraint_type=ConstraintType.UNIQUE,
            )
            constraint_obj = DBConstraint(
                table_name=table_name,
                constraint_name=constraint_name,
                columns=frozenset(constraint.columns),
                constraint_type=ConstraintType.UNIQUE,
            )
            yield constraint_obj, [
                table_ptr,
                *[
                    DBColumnPointer(table_name=table_name, column_name=column)
                    for column in constraint.columns
                ],
            ]
        elif isinstance(constraint, IndexConstraint):
            pass  # IndexConstraint is not represented in the database

    def handle_primary_keys(
        self, keys: list[tuple[str, DBFieldInfo]], table: Type[TableBase]
    ):
        table_name = table.get_table_name()
        # Save a pointer to the table for use in dependencies
        table_ptr = DBTable(table_name=table_name)

        # Put the primary key constraint on all columns with primary_key=True
        key_names = [k[0] for k in keys]
        constraint_name = DBConstraint.new_constraint_name(
            table_name=table_name,
            columns=key_names,
            constraint_type=ConstraintType.PRIMARY_KEY,
        )

        # Create constraint
        constraint = DBConstraint(
            table_name=table_name,
            constraint_name=constraint_name,
            columns=frozenset(key_names),
            constraint_type=ConstraintType.PRIMARY_KEY,
        )
        yield constraint, [
            table_ptr,
            *[
                DBColumnPointer(table_name=table_name, column_name=key_name)
                for key_name in key_names
            ],
        ]

    def _yield_nodes(
        self,
        child: NodeYieldType | Generator[NodeYieldType, None, None],
        dependencies: Sequence[NodeYieldType] | None = None,
        force_no_dependencies: bool = False,
    ) -> list[NodeDefinition]:
        """
        Helper method for yielding nodes from a generator.

        """

        def _format_dependencies(dependencies: Sequence[NodeYieldType]):
            result: list[DBObject | DBObjectPointer] = []
            for dep in dependencies:
                if isinstance(dep, NodeDefinition):
                    result.append(dep.node)
                else:
                    result.append(dep)
            return result

        if isgenerator(child):
            defs = []
            for node in child:
                defs.extend(
                    self._yield_nodes(
                        node, dependencies, force_no_dependencies=force_no_dependencies
                    )
                )
            return defs

        if isinstance(child, tuple) and len(child) == 2:
            # If we get a (node, deps) tuple from a handler, those deps
            # should be added to the existing dependencies
            child_node, child_deps = child
            if not isgenerator(child_node):
                deps = []
                if dependencies:
                    deps.extend(_format_dependencies(dependencies))
                if child_deps:
                    deps.extend(_format_dependencies(child_deps))
                return [
                    NodeDefinition(
                        node=child_node, dependencies=deps, force_no_dependencies=False
                    )
                ]
            else:
                # Generator inside a tuple?!?!, just yield the nodes with the deps
                defs = []
                for node in child_node:
                    defs.extend(
                        self._yield_nodes(
                            node, child_deps, force_no_dependencies=force_no_dependencies
                        )
                    )
                return defs
        else:
            # Just a bare node, pass the dependencies down
            if not isinstance(child, DBObject) and not isinstance(
                child, DBObjectPointer
            ):
                raise ValueError(f"Expected DBObject or DBObjectPointer, got {child}")
            return [
                NodeDefinition(
                    node=child,
                    dependencies=_format_dependencies(dependencies or []),
                    force_no_dependencies=force_no_dependencies,
                )
            ]


class DBRLSEnabled(DBObject):
    """
    Represents the RLS enablement state for a table.
    """
    table_name: str
    force: bool = False

    def representation(self) -> str:
        return f"{self.table_name}_rls_enabled"

    async def create(self, actor: DatabaseActions):
        await actor.enable_rls(self.table_name, self.force)

    async def migrate(self, previous: "DBRLSEnabled", actor: DatabaseActions):
        if self.force != previous.force:
            if self.force:
                await actor.force_rls(self.table_name)
            else:
                await actor.no_force_rls(self.table_name)

    async def destroy(self, actor: DatabaseActions):
        await actor.disable_rls(self.table_name)
