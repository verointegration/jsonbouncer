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


class StopValidation(Exception):
    """Thrown to stop proceeding validators from being run on a field."""
    def __init__(self, data):
        self.data = data


class Invalid(Exception):
    """Thrown when a field contains invalid data.

    :attr message: The error message.
    :attr path: The path to the error as a list of keys in the source data.
    :attr data: The data that caused the exception to be thrown.
    """

    def __init__(self, message, data=None, path=None):
        Exception.__init__(self, message)
        self.path = path or []
        self.data = data

    def __str__(self):
        path = ""
        if self.path:
            path = " @ data[{0}]".format("][".join(map(str, self.path)))
        return Exception.__str__(self) + path

    def __repr__(self):
        return "Invalid(\"{0}\", [{1}])".format(
            self.message, ", ".join([str(p) for p in self.path]))


class InvalidGroup(Invalid):
    """Thrown when a field has multiple validators fail.

    :attr errors: Two or more objects of the Invalid type.
    """

    def __init__(self, errors=None, data=None):
        self.errors = errors[:] if errors else []
        self.data = data

    def __str__(self):
        return "\n".join([str(e) for e in self.errors])

    def __repr__(self):
        return "InvalidGroup([{0}])".format(", ".join(map(repr, self.errors)))


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

    def __init__(self, schema):
        """Create a new schema.

        :param schema: Validation schema. See :module:`validation` for details.
        """
        self.schema = schema

    def __call__(self, data):
        """Validate data against this schema."""
        try:
            data = self._validate(self.schema, data, [])
        except InvalidGroup as e:
            raise e
        except Invalid as e:
            raise InvalidGroup([e])
        return data

    @classmethod
    def _validate(cls, schema, data, path):
        """Determines the validation function to call based on the schema type.

        :param schema: The schema to validate the data against.
        :param data: The data to validate.
        :param path: The path of the current set of data.
        """
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
        raised with a message specifying the type of data expected.

        :param schema: The built-in data type, such as str, int, etc.
        :param data: The data to validate.
        :param path: The path of the passed in data.
        """
        if data is Undefined:
            return data
        if not isinstance(data, schema):
            raise Invalid("Expected {0}".format(schema.__name__), data, path)
        return data

    @classmethod
    def _validate_function(cls, schema, data, path):
        """Calls a schema specified function to validate data.

        This method will call the given function to validate data. The function
        should return the munged or unchanged value when validation is
        successful. If validation fails, either an Invalid exception or an
        InvalidGroup exception should be raised. The method will also catch and
        handle ValueError exceptions by raising an Invalid exception.
        """
        try:
            return schema(data)
        except ValueError:
            raise Invalid("Invalid value given", data, path)
        except InvalidGroup as e:
            errors = []
            for invalid in e.errors:
                errors.append(
                    Invalid(invalid.message, data, path + invalid.path))
            raise InvalidGroup(errors, data)
        except Invalid as e:
            raise Invalid(e.message, data, path + e.path)

    @classmethod
    def _validate_dict(cls, schema, data, path):
        """Validates a dictionary object key-by-key.

        This method will loop through each key in a schema and apply that key's
        validation functions to the data. Validation will be run on all keys
        even if previous keys failed validation. If validation fails on one or
        more keys, an InvalidGroup exception will be raised, otherwise the post
        validated data (possibly munged by the validation functions) will
        be returned.
        """
        if not isinstance(data, dict):
            raise Invalid("Expected an object", data, path)
        # If the schema is empty, all data is allowed
        if not schema:
            return data
        # Loop through each entry in the schema and validate
        output = {}
        errors = []
        for key, value in schema.iteritems():
            new_path = path + [key]
            new_data = Undefined if key not in data else data[key]
            try:
                retval = cls._validate(value, new_data, new_path)
                if retval is not Undefined:
                    output[key] = retval
            except InvalidGroup as e:
                errors += e.errors
                output[key] = e
            except Invalid as e:
                errors.append(e)
                output[key] = e
        if errors:
            raise InvalidGroup(errors, output)
        return output

    @classmethod
    def _validate_list(cls, schema, data, path):
        """Validates each item in a list with the given schema.

        This method loops through and validates each item of a passed in data
        list. The validation schema is applied to each item in the list in
        order. All items are validated, even if a previous item has already
        failed validation. After validating all items, an InvalidGroup
        exception is raised if one or more items failed validation, otherwise
        the list of validated items is returned.
        """
        if not isinstance(data, list):
            raise Invalid("Expected a list", data, path)
        # If the schema is empty, all data is allowed
        if not schema:
            return data
        # Loop through each entry in the list and validate
        output = []
        errors = []
        for i, new_data in enumerate(data):
            new_path = path + [i]
            error = None
            for new_schema in schema:
                try:
                    retval = cls._validate(new_schema, new_data, new_path)
                    output.append(retval)
                    break
                except InvalidGroup as e:
                    error = e
                except Invalid as e:
                    error = e
            else:
                if isinstance(error, InvalidGroup):
                    errors += error.errors
                else:
                    errors.append(error)
                output.append(error)
        if errors:
            raise InvalidGroup(errors, output)
        return output


def Any(*schemas):
    """Returns the value of the first schema entry that validates.

    A schema entry is determined to be valid if it does not raise an Invalid
    exception. This means Any() will be satisfied by any return value
    (including Undefined, None, 0, etc.)."""
    def inner(data):
        if schemas:
            error = None
            for schema in schemas:
                try:
                    data = Schema._validate(schema, data, [])
                    break
                except StopValidation as e:
                    if isinstance(e.data, Invalid):
                        error = e.data
                    else:
                        data = e.data
                    break
                except Invalid as e:
                    error = e
                except InvalidGroup as e:
                    error = e
            else:
                raise error
        return data
    return inner


def All(*schemas):
    """Returns a value if it validates all schema entries passed.

    A value is determined to be valid and returned if all schema entries passed
    in validate. A schema entry is determined to be valid if it does not raise
    an Invalid exception."""
    def inner(data):
        if schemas:
            for schema in schemas:
                try:
                    data = Schema._validate(schema, data, [])
                except StopValidation as e:
                    if isinstance(e.data, Invalid):
                        raise e.data
                    data = e.data
                    break
        return data
    return inner


def Chain(*schemas):
    def inner(data):
        if schemas:
            error = None
            for schema in schemas:
                try:
                    data = Schema._validate(schema, data, [])
                    error = None
                except StopValidation as e:
                    data = e.data
                    if isinstance(e.data, Invalid):
                        error = e.data
                    break
                except Invalid as e:
                    data = e
                    error = e
                except InvalidGroup as e:
                    data = e
                    error = e
            if error:
                raise error
        return data
    return inner
