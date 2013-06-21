# -*- coding: utf-8 -*-
"""Schema validation for JSON data.
"""

from __future__ import division, unicode_literals


__author__ = "Kevin Peel <kevin.peel@verointegration.com"
__version__ = "0.0.1"


class _Undefined(object):
    """ Used to denote an unset or undefined value within the data."""

    def __nonzero__(self):
        return False

    def __repr__(self):
        return "..."


Undefined = _Undefined()


class SkipValidation(Exception):
    """Thrown to stop proceeding validators from being run on a field."""


class Invalid(Exception):
    """Thrown when a field contains invalid data.

    :attr message: The error message.
    :attr path: The path to the error as a list of keys in the source data.
    """

    def __init__(self, message, path=None):
        Exception.__init__(self, message)
        self.path = path or []

    def __str__(self):
        path = ""
        if self.path:
            path = " @ data[{0}]".format("][".join(map(str, self.path)))
        return Exception.__str__(self) + path


class InvalidGroup(Invalid):
    """Thrown when a field has multiple validators fail.

    :attr errors: Two or more objects of the Invalid type.
    """

    def __init__(self, errors=None):
        self.errors = errors[:] if errors else []

    def __str__(self):
        return str(self.errors[0])


class SchemaError(Exception):
    """Thrown when an invalid schema is passed"""


class Schema(object):
    """A validation schema.

    The schema is a Python tree-like structure where nodes are pattern
    matched against corresponding trees of values.

    Nodes can be values, in which case a direct comparison is used, types,
    in which case an isinstance() check is performed, or callables, which will
    validate and optionally convert the value.
    """

    def __init__(self, *schemas):
        """Create a new schema.

        :param schema: Validation schema. See :module:`validation` for details.
        """
        self.schema = schemas[0]
        for schema in schemas[1:]:
            self.schema = self._merge_schemas(self.schema, schema)

    def __call__(self, data):
        """Validate data against this schema."""
        data, errors = self._validate(self.schema, data, [])
        if errors:
            raise InvalidGroup(errors)
        return data

    @classmethod
    def _validate(cls, schema, data, path):
        # String, Number, Boolean, None
        if schema == str:
            schema = unicode
        if schema in (int, long, unicode, float, bool, None):
            return cls._validate_type(schema, data, path)
        # Function
        if callable(schema):
            return cls._validate_function(schema, data, path)
        # Object
        if isinstance(schema, dict):
            return cls._validate_dict(schema, data, path)
        # Array
        if isinstance(schema, list):
            return cls._validate_list(schema, data, path)
        raise SchemaError("Unsupported schema data type: {0}".format(schema))

    @classmethod
    def _validate_type(cls, schema, data, path):
        """Validates that data is of a specific built-in type.

        This method determines if data is a specific built-in Python type. If
        the data is not the type specified by schema, an Invalid error is
        returned with a message specifying the type of data expected.

        :param schema: The built-in data type, such as str, int, etc.
        :param data: The data to validate.
        :param path: The path of the passed in data.
        """
        if data is Undefined:
            return data, []
        if not isinstance(data, schema):
            error = Invalid("Expected {0}".format(schema.__name__), path)
            return error, [error]
        return data, []

    @classmethod
    def _validate_function(cls, schema, data, path):
        try:
            return schema(data), []
        except ValueError as e:
            ex = Invalid("Invalid value given", path)
            return ex, [ex]
        except InvalidGroup as e:
            errors = []
            for invalid in e.errors:
                errors.append(Invalid(invalid.message, path + invalid.path))
            modified_ex = InvalidGroup(errors)
            return modified_ex, errors
        except Invalid as e:
            modified_ex = Invalid(e.message, path + e.path)
            return modified_ex, [modified_ex]

    @classmethod
    def _validate_dict(cls, schema, data, path):
        if not isinstance(data, dict):
            error = Invalid("Expected an object", path)
            return error, [error]
        output = {}
        errors = []
        # If the schema is empty, all data is allowed
        if not schema:
            return data, errors
        # Loop through each entry in the schema and validate
        for key, value in schema.iteritems():
            new_path = path + [key]
            new_data = Undefined if key not in data else data[key]
            retval, error = cls._validate(value, new_data, new_path)
            if retval is not Undefined:
                output[key] = retval
            errors += error
        return output, errors

    @classmethod
    def _validate_list(cls, schema, data, path):
        if not isinstance(data, list):
            error = Invalid("Expected a list", path)
            return error, [error]
        # If the schema is empty, all data is allowed
        if not schema:
            return data, []
        output = []
        errors = []
        for i, new_data in enumerate(data):
            new_path = path + [i]
            error = []
            for new_schema in schema:
                retval, error = cls._validate(new_schema, new_data, new_path)
                if not error:
                    break
            output.append(retval)
            errors += error
        return output, errors


def Any(*schemas, **kwargs):
    """Returns the value of the first schema entry that validates.

    A schema entry is determined to be valid if it does not raise an Invalid
    exception. This means Any() will be satisfied by any return value
    (including Undefined, None, 0, etc.)."""
    def inner(data):
        if schemas:
            for schema in schemas:
                retval, error = Schema._validate(schema, data, [])
                if not error:
                    break
            else:
                raise retval
        when_var = None
        if data == 0 and type(data) != bool and "when_zero" in kwargs:
            when_var = kwargs["when_zero"]
        elif data is False and "when_false" in kwargs:
            when_var = kwargs["when_false"]
        elif data is None and "when_none" in kwargs:
            when_var = kwargs["when_none"]
        elif data == "" and "when_empty_str" in kwargs:
            when_var = kwargs["when_empty_str"]
        elif data is Undefined and "when_undefined" in kwargs:
            when_var = kwargs["when_undefined"]
        elif not bool(data) and "when_empty" in kwargs:
            when_var = kwargs["when_empty"]
        if when_var:
            if when_var == Invalid:
                raise Invalid("A value is required")
            if isinstance(when_var, Invalid):
                raise when_var
            if callable(when_var):
                return when_var(data)
            return when_var
        return data
    return inner


def All(*schemas, **kwargs):
    """Returns a value if it validates all schema entries passed.

    A value is determined to be valid and returned if all schema entries passed
    in validate. A schema entry is determined to be valid if it does not raise
    an Invalid exception."""
    def inner(data):
        if schemas:
            for schema in schemas:
                retval, error = Schema._validate(schema, data, [])
                if error:
                    raise retval
                data = retval
        when_var = None
        if data == 0 and type(data) != bool and "when_zero" in kwargs:
            when_var = kwargs["when_zero"]
        elif data is False and "when_false" in kwargs:
            when_var = kwargs["when_false"]
        elif data is None and "when_none" in kwargs:
            when_var = kwargs["when_none"]
        elif data == "" and "when_empty_str" in kwargs:
            when_var = kwargs["when_empty_str"]
        elif data is Undefined and "when_undefined" in kwargs:
            when_var = kwargs["when_undefined"]
        elif not bool(data) and "when_empty" in kwargs:
            when_var = kwargs["when_empty"]
        if when_var:
            if when_var == Invalid:
                raise Invalid("A value is required")
            if isinstance(when_var, Invalid):
                raise when_var
            if callable(when_var):
                return when_var(data)
            return when_var
        return data
    return inner
