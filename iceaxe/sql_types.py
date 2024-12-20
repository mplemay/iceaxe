from datetime import date, datetime, time, timedelta
from enum import Enum, StrEnum
from uuid import UUID


class ColumnType(StrEnum):
    # The values of the enum are the actual SQL types. When constructing
    # the column they can be case-insensitive, but when we're casting from
    # the database to memory they must align with the on-disk representation
    # which is lowercase.

    # Numeric Types
    SMALLINT = "smallint"
    INTEGER = "integer"
    BIGINT = "bigint"
    DECIMAL = "decimal"
    NUMERIC = "numeric"
    REAL = "real"
    DOUBLE_PRECISION = "double precision"
    SERIAL = "serial"
    BIGSERIAL = "bigserial"

    # Monetary Type
    MONEY = "money"

    # Character Types
    CHAR = "char"
    VARCHAR = "character varying"
    TEXT = "text"

    # Binary Data Types
    BYTEA = "bytea"

    # Date/Time Types
    DATE = "date"
    TIME = "time"
    TIME_WITH_TIME_ZONE = "time with time zone"
    TIMESTAMP = "timestamp"
    TIMESTAMP_WITH_TIME_ZONE = "timestamp with time zone"
    INTERVAL = "interval"

    # Boolean Type
    BOOLEAN = "boolean"

    # Geometric Types
    POINT = "point"
    LINE = "line"
    LSEG = "lseg"
    BOX = "box"
    PATH = "path"
    POLYGON = "polygon"
    CIRCLE = "circle"

    # Network Address Types
    CIDR = "cidr"
    INET = "inet"
    MACADDR = "macaddr"
    MACADDR8 = "macaddr8"

    # Bit String Types
    BIT = "bit"
    BIT_VARYING = "bit varying"

    # Text Search Types
    TSVECTOR = "tsvector"
    TSQUERY = "tsquery"

    # UUID Type
    UUID = "uuid"

    # XML Type
    XML = "xml"

    # JSON Types
    JSON = "json"
    JSONB = "jsonb"

    # Range Types
    INT4RANGE = "int4range"
    NUMRANGE = "numrange"
    TSRANGE = "tsrange"
    TSTZRANGE = "tstzrange"
    DATERANGE = "daterange"

    # Object Identifier Type
    OID = "oid"


class ConstraintType(StrEnum):
    PRIMARY_KEY = "PRIMARY KEY"
    FOREIGN_KEY = "FOREIGN KEY"
    UNIQUE = "UNIQUE"
    CHECK = "CHECK"
    INDEX = "INDEX"


def get_python_to_sql_mapping():
    """
    Returns a mapping of Python types to their corresponding SQL types.
    """
    return {
        int: ColumnType.INTEGER,
        float: ColumnType.DOUBLE_PRECISION,
        str: ColumnType.VARCHAR,
        bool: ColumnType.BOOLEAN,
        bytes: ColumnType.BYTEA,
        UUID: ColumnType.UUID,
        datetime: ColumnType.TIMESTAMP,
        date: ColumnType.DATE,
        time: ColumnType.TIME,
        timedelta: ColumnType.INTERVAL,
    }


def enum_to_name(enum: Enum) -> str:
    """
    Returns the name of the enum as a string.
    """
    return enum.__name__.lower()
