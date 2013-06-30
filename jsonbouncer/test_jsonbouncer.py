# -*- coding: utf-8 -*-
# pylint: disable-all
from __future__ import division, unicode_literals

import unittest
from mock import Mock, call, patch

from jsonbouncer import (
    Schema, Invalid, InvalidGroup, StopValidation, Undefined, SchemaError,
    Any, All, Chain)
from validators import (
    coerce_to, in_range, in_list, require_one, require_if,
    _when_base, when_empty, when_zero, when_false, when_none,
    when_empty_str, when_undefined)


class TestUndefined(unittest.TestCase):
    def test_undefined_acts_as_a_falsey_object(self):
        self.assertFalse(bool(Undefined))
        self.assertTrue(not Undefined)

    def test_undefined_returns_an_ellipsis_as_its_str(self):
        self.assertEqual(str(Undefined), "...")


class TestInvalid(unittest.TestCase):
    def test_creating_an_invalid_exception_saves_the_passed_in_message(self):
        instance = Invalid("Invalid message")
        self.assertEqual(instance.message, "Invalid message")

    def test_creating_an_invalid_exception_saves_the_passed_in_data(self):
        instance = Invalid("")
        self.assertIsNone(instance.data)
        instance = Invalid("", 123)
        self.assertEqual(instance.data, 123)
        instance = Invalid("", data=123)
        self.assertEqual(instance.data, 123)

    def test_creating_an_invalid_exception_saves_the_passed_in_path(self):
        instance = Invalid("")
        self.assertEqual(instance.path, [])
        instance = Invalid("", None, [1, "b", 3])
        self.assertEqual(instance.path, [1, "b", 3])
        instance = Invalid("", path=[1, "b", 3])
        self.assertEqual(instance.path, [1, "b", 3])

    def test_invalid_exception_prints_path_if_given(self):
        instance = Invalid("Invalid message")
        self.assertEqual(str(instance), "Invalid message")
        instance = Invalid("Invalid message", path=[1, "b", 3])
        self.assertEqual(str(instance), "Invalid message @ data[1][b][3]")

    def test_invalid_exception_repr_returns_invalid_object(self):
        instance = Invalid("Invalid message")
        self.assertEqual(repr(instance), "Invalid(\"Invalid message\", [])")
        instance = Invalid("Invalid message", path=[1, "b", 3])
        self.assertEqual(
            repr(instance), "Invalid(\"Invalid message\", [1, b, 3])")


class TestInvalidGroup(unittest.TestCase):
    def test_creating_an_invalid_group_saves_the_passed_in_errors(self):
        instance = InvalidGroup([1, 2])
        self.assertEqual(instance.errors, [1, 2])

    def test_creating_an_invalid_group_saves_the_passed_in_data(self):
        instance = InvalidGroup([], "abc")
        self.assertEqual(instance.data, "abc")

    def test_invalid_group_returns_all_error_messages_as_its_str(self):
        instance = InvalidGroup([Invalid("a", path=[1]), Invalid("b")])
        self.assertEqual(str(instance), "a @ data[1]\nb")

    def test_invalid_group_repr_returns_invalid_group_object(self):
        instance = InvalidGroup([Invalid("a", path=[1]), Invalid("b")])
        self.assertEqual(
            repr(instance),
            "InvalidGroup([Invalid(\"a\", [1]), Invalid(\"b\", [])])")


class TestSchema(unittest.TestCase):
    def test_creating_a_schema_saves_the_passed_in_schema(self):
        schema = {"a": "b", "k": "l", "y": 3}
        instance = Schema(schema)
        self.assertEqual(instance.schema, {"a": "b", "k": "l", "y": 3})

    def test_calling_a_schema_returns_data_when_data_is_valid(self):
        mocked = Mock(return_value=1)
        with patch.object(Schema, "_validate", mocked):
            instance = Schema({"a": int})
            retval = instance({"a": 1})
            self.assertEqual(retval, 1)

    def test_calling_a_schema_raises_invalid_group_when_data_is_invalid(self):
        invalid = Invalid("abc")
        mocked = Mock(side_effect=invalid)
        with patch.object(Schema, "_validate", mocked):
            with self.assertRaises(InvalidGroup) as cm:
                instance = Schema({"a": int})
                instance({"a": 1})
            self.assertEqual(map(str, cm.exception.errors), ["abc"])
        invalid = InvalidGroup([Invalid("def"), Invalid("ghi")])
        mocked = Mock(side_effect=invalid)
        with patch.object(Schema, "_validate", mocked):
            with self.assertRaises(InvalidGroup) as cm:
                instance = Schema({"a": int})
                instance({"a": 1})
            self.assertEqual(map(str, cm.exception.errors), ["def", "ghi"])


class TestSchemaValidate(unittest.TestCase):
    def test_validate_raises_schema_error_when_a_bad_schema_is_passed(self):
        with self.assertRaises(SchemaError) as cm:
            instance = Schema("a")
            instance("b")
        self.assertEqual(str(cm.exception), "Unsupported schema data type: a")

    def test_validate_calls_validate_dict_when_passed_a_dict_schema(self):
        with patch.object(Schema, "_validate_dict") as mocked:
            Schema._validate({}, {}, [])
            mocked.assert_called_once_with({}, {}, [])

    def test_validate_calls_validate_list_when_passed_a_list_schema(self):
        with patch.object(Schema, "_validate_list") as mocked:
            Schema._validate([], [], [])
            mocked.assert_called_once_with([], [], [])

    def test_validate_calls_validate_function_when_passed_a_function(self):
        with patch.object(Schema, "_validate_function") as mocked:
            mock_function = Mock()
            Schema._validate(mock_function, "data", [])
            mocked.assert_called_once_with(mock_function, "data", [])

    def test_validate_calls_validate_type_when_passed_a_type_schema(self):
        with patch.object(Schema, "_validate_type") as mocked:
            Schema._validate(int, 12, [])
            mocked.assert_called_once_with(int, 12, [])
            mocked.reset_mock()
            Schema._validate(float, 12.1, [])
            mocked.assert_called_once_with(float, 12.1, [])
            mocked.reset_mock()
            Schema._validate(unicode, "a string", [])
            mocked.assert_called_once_with(unicode, "a string", [])
            mocked.reset_mock()
            Schema._validate(long, 12345678901234, [])
            mocked.assert_called_once_with(long, 12345678901234, [])
            mocked.reset_mock()
            Schema._validate(bool, True, [])
            mocked.assert_called_once_with(bool, True, [])
            mocked.reset_mock()
            Schema._validate(None, None, [])
            mocked.assert_called_once_with(None, None, [])

    def test_validate_calls_validate_type_with_unicode_when_passed_a_str(self):
        with patch.object(Schema, "_validate_type") as mocked:
            data = str("a string")
            Schema._validate(str, data, [])
            mocked.assert_called_once_with(unicode, data, [])


class TestSchemaValidateType(unittest.TestCase):
    def test_validate_type_returns_the_data_when_valid(self):
        self.assertEqual(Schema._validate_type(unicode, "", []), "")
        self.assertEqual(Schema._validate_type(int, 0, []), 0)
        self.assertEqual(Schema._validate_type(bool, False, []), False)

    def test_validate_type_returns_undefined_when_passed_undefined(self):
        self.assertEqual(
            Schema._validate_type(unicode, Undefined, []), Undefined)
        self.assertEqual(
            Schema._validate_type(int, Undefined, []), Undefined)

    def test_validate_type_raises_invalid_on_invalid_data(self):
        with self.assertRaises(Invalid) as cm:
            Schema._validate_type(unicode, 1, [])
        self.assertEqual(str(cm.exception), "Expected unicode")
        self.assertEqual(cm.exception.data, 1)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_type(int, "abc", [1])
        self.assertEqual(str(cm.exception), "Expected int @ data[1]")
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(Invalid) as cm:
            Schema._validate_type(bool, None, ["a", 0, "b"])
        self.assertEqual(str(cm.exception), "Expected bool @ data[a][0][b]")
        self.assertEqual(cm.exception.data, None)


class TestSchemaValidateDict(unittest.TestCase):
    # Invalid when data is not a dict
    # Unmodified when schema is empty
    # Returns dict with munged values if valid
    # Raises InvalidGroup error if one or more entries is invalid
    def test_validate_dict_raises_invalid_if_not_given_a_dictionary(self):
        with self.assertRaises(Invalid) as cm:
            Schema._validate_dict({}, [], [])
        self.assertEqual(str(cm.exception), "Expected an object")
        self.assertEqual(cm.exception.data, [])
        with self.assertRaises(Invalid) as cm:
            Schema._validate_dict({}, Undefined, [0])
        self.assertEqual(str(cm.exception), "Expected an object @ data[0]")
        self.assertEqual(cm.exception.data, Undefined)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_dict({}, None, ["a", "b"])
        self.assertEqual(str(cm.exception), "Expected an object @ data[a][b]")
        self.assertEqual(cm.exception.data, None)

    def test_validate_dict_returns_all_data_if_schema_is_empty(self):
        self.assertEqual(
            Schema._validate_dict({}, {"a": 1, "b": None}, []),
            {"a": 1, "b": None})

    def test_validate_dict_returns_defined_values_from_validation(self):
        def mock_return(schema, data, path):
            return data
        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = {"a": int, "b": int, "c": int, "d": int}
            data = {"a": 1, "c": 2, "d": 3}
            self.assertEqual(Schema._validate_dict(schema, data, []), data)

    def test_validate_dict_raises_invalid_group_for_invalid_data(self):
        def mock_return(schema, data, path):
            if data is Undefined:
                return Undefined
            if not isinstance(data, schema):
                raise Invalid("err", data, path)
            return data
        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            with self.assertRaises(InvalidGroup) as cm:
                schema = {"a": int, "b": int, "c": int, "d": int}
                data = {"a": None, "b": 1, "c": 2}
                Schema._validate_dict(schema, data, [])
            self.assertEqual(map(str, cm.exception.errors), ["err @ data[a]"])
            self.assertEqual([e.data for e in cm.exception.errors], [None])
            with self.assertRaises(InvalidGroup) as cm:
                schema = {"a": int, "b": int, "c": int, "d": int}
                data = {"a": 1, "c": 1.1, "d": "abc"}
                Schema._validate_dict(schema, data, [])
            self.assertEqual(
                map(str, cm.exception.errors),
                ["err @ data[c]", "err @ data[d]"])
            self.assertEqual(
                [e.data for e in cm.exception.errors], [1.1, "abc"])
            with self.assertRaises(InvalidGroup) as cm:
                schema = {"a": int, "b": int, "c": int, "d": int}
                data = {"a": 1, "b": 2, "c": 2.0, "d": None}
                Schema._validate_dict(schema, data, ["x", 1])
            self.assertEqual(
                map(str, cm.exception.errors),
                ["err @ data[x][1][c]", "err @ data[x][1][d]"])
            self.assertEqual(
                [e.data for e in cm.exception.errors], [2.0, None])

    def test_validate_dict_calls_validate_once_for_each_key(self):
        # TODO: Should we be checking this, or just checking the output?
        mocked = Mock(return_value={})
        with patch.object(Schema, "_validate", mocked):
            schema = {"a": unicode, "c": int, "e": unicode, "g": bool}
            data = {"a": "b", "c": 4, "e": "f", "g": True}
            Schema._validate_dict(schema, data, [])
            mocked.assert_has_calls([
                call(unicode, "b", ["a"]),
                call(int, 4, ["c"]),
                call(unicode, "f", ["e"]),
                call(bool, True, ["g"])
            ], any_order=True)

    def test_validate_dict_appends_the_key_to_the_current_path(self):
        # TODO: Should we be checking this, or just the output?
        # TODO: If we do decide to keep this, it should be combined with above
        mocked = Mock(return_value={})
        with patch.object(Schema, "_validate", mocked):
            schema = {"a": int, "b": int, "c": int}
            data = {"a": 1, "b": 2, "c": 3}
            Schema._validate_dict(schema, data, [])
            mocked.assert_has_calls([
                call(int, 1, ["a"]),
                call(int, 2, ["b"]),
                call(int, 3, ["c"])
            ], any_order=True)

            mocked.reset_mock()
            Schema._validate_dict(schema, data, ["f"])
            mocked.assert_has_calls([
                call(int, 1, ["f", "a"]),
                call(int, 2, ["f", "b"]),
                call(int, 3, ["f", "c"])
            ], any_order=True)

            mocked.reset_mock()
            Schema._validate_dict(schema, data, ["f", "g", 1])
            mocked.assert_has_calls([
                call(int, 1, ["f", "g", 1, "a"]),
                call(int, 2, ["f", "g", 1, "b"]),
                call(int, 3, ["f", "g", 1, "c"])
            ], any_order=True)

    def test_validate_dict_passes_undefined_if_a_value_isnt_in_data(self):
        mocked = Mock(return_value={})
        with patch.object(Schema, "_validate", mocked):
            data = {"a": 1, "c": 2}
            schema = {"a": int, "b": int, "c": int, "d": int}
            Schema._validate_dict(schema, data, [])
            mocked.assert_has_calls([
                call(int, 1, ["a"]),
                call(int, Undefined, ["b"]),
                call(int, 2, ["c"]),
                call(int, Undefined, ["d"])
            ], any_order=True)


class TestSchemaValidateList(unittest.TestCase):
    def test_validate_list_raises_invalid_if_not_given_a_list(self):
        with self.assertRaises(Invalid) as cm:
            Schema._validate_list([], {}, [])
        self.assertEqual(str(cm.exception), "Expected a list")
        self.assertEqual(cm.exception.data, {})
        with self.assertRaises(Invalid) as cm:
            Schema._validate_list([], Undefined, [1])
        self.assertEqual(str(cm.exception), "Expected a list @ data[1]")
        self.assertEqual(cm.exception.data, Undefined)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_list([], None, ["a", "b"])
        self.assertEqual(str(cm.exception), "Expected a list @ data[a][b]")
        self.assertEqual(cm.exception.data, None)

    def test_validate_list_returns_unmodified_data_when_schema_is_empty(self):
        self.assertEqual(
            Schema._validate_list([], [1, 2, 3], []), [1, 2, 3])

    def test_validate_list_returns_values_from_validation(self):
        def mock_return(schema, data, path):
            if not isinstance(data, schema):
                raise Invalid("", data, path)
            if schema == unicode:
                return "{0}r".format(data)
            return data + 1
        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = [unicode, int]
            data = ["z", 1, "y", 2, "x", 3, "w"]
            val = Schema._validate_list(schema, data, [])
            self.assertEqual(val, ["zr", 2, "yr", 3, "xr", 4, "wr"])

    def test_validate_list_raises_invalid_group_on_invalid_data(self):
        def mock_return(schema, data, path):
            if not isinstance(data, schema):
                raise Invalid("err", data, path)
            return data
        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            with self.assertRaises(InvalidGroup) as cm:
                schema = [unicode, int]
                data = [1, "a", 1.2, "b", 2, None]
                Schema._validate_list(schema, data, ["a", 2])
            ex = cm.exception
            self.assertEqual(
                map(str, ex.errors),
                ["err @ data[a][2][2]", "err @ data[a][2][5]"])
            self.assertEqual([e.data for e in ex.errors], [1.2, None])
            self.assertEqual(
                ex.data, [1, "a", ex.errors[0], "b", 2, ex.errors[1]])

    # TODO: Not sure these are necessary. Should be tested in above tests
    def test_validate_list_calls_validate_for_each_data_entry(self):
        mocked = Mock(return_value=1)
        with patch.object(Schema, "_validate", mocked):
            Schema._validate_list([int], [], [])
            self.assertFalse(mocked.called)
            mocked.reset_mock()
            Schema._validate_list([int], [1], [])
            mocked.assert_called_once_with(int, 1, [0])
            mocked.reset_mock()
            Schema._validate_list([int], [1, 2, 3], [])
            mocked.assert_has_calls([
                call(int, 1, [0]),
                call(int, 2, [1]),
                call(int, 3, [2])
            ])

    def test_validate_list_calls_validate_for_schema_values_as_necessary(self):
        def mock_return(schema, data, path):
            if not isinstance(data, schema):
                raise Invalid("")
            return data
        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            Schema._validate_list([int, unicode], [], [])
            self.assertFalse(mocked.called)
            mocked.reset_mock()
            Schema._validate_list([int, unicode], ["a"], [])
            mocked.assert_has_calls([
                call(int, "a", [0]),
                call(unicode, "a", [0])
            ])
            mocked.reset_mock()
            Schema._validate_list([int, unicode], [1], [])
            mocked.assert_called_once_with(int, 1, [0])
            mocked.reset_mock()
            with self.assertRaises(InvalidGroup):
                Schema._validate_list([int, unicode], [None], [])
            mocked.assert_has_calls([
                call(int, None, [0]),
                call(unicode, None, [0])
            ])

    def test_validate_list_calls_validate_for_each_schema_data_combo(self):
        def mock_return(schema, data, path):
            if not isinstance(data, schema):
                raise Invalid("")
            return data

        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            Schema._validate_list([int, unicode], ["a", "b"], [])
            mocked.assert_has_calls([
                call(int, "a", [0]),
                call(unicode, "a", [0]),
                call(int, "b", [1]),
                call(unicode, "b", [1])
            ])
            mocked.reset_mock()
            with self.assertRaises(InvalidGroup):
                Schema._validate_list([int, unicode], ["a", 1, None], [])
            mocked.assert_has_calls([
                call(int, "a", [0]),
                call(unicode, "a", [0]),
                call(int, 1, [1]),
                call(int, None, [2]),
                call(unicode, None, [2])
            ])
            mocked.reset_mock()
            Schema._validate_list([int, unicode], [1, 2], [])
            mocked.assert_has_calls([
                call(int, 1, [0]),
                call(int, 2, [1]),
            ])

    def test_validate_list_appends_the_entry_index_to_the_current_path(self):
        mocked = Mock(return_value=1)
        with patch.object(Schema, "_validate", mocked):
            data = ["a", "b", "c"]
            Schema._validate_list([unicode], data, [])
            mocked.assert_has_calls([
                call(unicode, "a", [0]),
                call(unicode, "b", [1]),
                call(unicode, "c", [2])
            ])
            mocked.reset_mock()
            Schema._validate_list([unicode], data, ["a"])
            mocked.assert_has_calls([
                call(unicode, "a", ["a", 0]),
                call(unicode, "b", ["a", 1]),
                call(unicode, "c", ["a", 2])
            ])
            mocked.reset_mock()
            Schema._validate_list([unicode], data, ["b", "c", 2])
            mocked.assert_has_calls([
                call(unicode, "a", ["b", "c", 2, 0]),
                call(unicode, "b", ["b", "c", 2, 1]),
                call(unicode, "c", ["b", "c", 2, 2])
            ])


class TestSchemaValidateFunction(unittest.TestCase):
    def test_validate_function_calls_the_function(self):
        func = Mock()
        Schema._validate_function(func, "abc", [])
        func.assert_called_once_with("abc")

    def test_validate_function_returns_the_value_from_the_function(self):
        func = Mock(return_value=1)
        self.assertEqual(Schema._validate_function(func, "abc", []), 1)

    def test_validate_function_catches_and_raises_invalid(self):
        invalid = Invalid("abc")
        func = Mock(side_effect=invalid)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_function(func, 2, [])
        self.assertEqual(str(cm.exception), "abc")
        self.assertEqual(cm.exception.data, 2)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_function(func, 3, [1, "a"])
        self.assertEqual(str(cm.exception), "abc @ data[1][a]")
        self.assertEqual(cm.exception.data, 3)

    def test_validate_function_catches_and_raises_invalid_group(self):
        invalid_group = InvalidGroup(
            [Invalid("abc"), Invalid("def", path=[3])])
        func = Mock(side_effect=invalid_group)
        with self.assertRaises(InvalidGroup) as cm:
            Schema._validate_function(func, 2, [])
        ex = cm.exception
        self.assertEqual(map(str, ex.errors), ["abc", "def @ data[3]"])
        self.assertEqual([e.data for e in ex.errors], [2, 2])
        self.assertEqual(ex.data, 2)
        with self.assertRaises(InvalidGroup) as cm:
            Schema._validate_function(func, 3, [1, "a"])
        ex = cm.exception
        self.assertEqual(
            map(str, ex.errors), ["abc @ data[1][a]", "def @ data[1][a][3]"])
        self.assertEqual([e.data for e in ex.errors], [3, 3])
        self.assertEqual(ex.data, 3)

    def test_validate_function_catches_value_errors_and_raises_invalid(self):
        func = Mock(side_effect=ValueError)
        with self.assertRaises(Invalid) as cm:
            Schema._validate_function(func, "abc", [])
        self.assertEqual(str(cm.exception), "Invalid value given")
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(Invalid) as cm:
            Schema._validate_function(func, "def", ["a"])
        self.assertEqual(str(cm.exception), "Invalid value given @ data[a]")
        self.assertEqual(cm.exception.data, "def")


class TestAnyFunction(unittest.TestCase):
    def test_any_returns_a_new_function(self):
        anyfunc = Any(int)
        self.assertTrue(callable(anyfunc))

    def test_any_with_no_schemas_always_returns_the_passed_in_data(self):
        anyfunc = Any()
        val = anyfunc(0)
        self.assertEqual(val, 0)
        val = anyfunc(Undefined)
        self.assertEqual(val, Undefined)
        val = anyfunc("abcdefg")
        self.assertEqual(val, "abcdefg")

    def test_any_returns_first_value_where_invalid_is_not_raised(self):
        invalid_1 = Mock(side_effect=Invalid("1"))
        invalid_2 = Mock(side_effect=Invalid("2"))
        invalid_3 = Mock(side_effect=Invalid("3"))
        invalid_4 = Mock(side_effect=Invalid("4"))
        valid = Mock(return_value=1)
        anyfunc = Any(invalid_1, invalid_2, invalid_3, valid, invalid_4)
        val = anyfunc("abcd")
        self.assertEqual(val, 1)
        invalid_1.assert_called_once_with("abcd")
        invalid_2.assert_called_once_with("abcd")
        invalid_3.assert_called_once_with("abcd")
        valid.assert_called_once_with("abcd")
        self.assertFalse(invalid_4.called)

    def test_any_raises_invalid_when_no_valid_value_exists(self):
        invalid_1 = Mock(side_effect=Invalid("1"))
        invalid_2 = Mock(side_effect=Invalid("2"))

        with self.assertRaises(Invalid):
            anyfunc = Any(invalid_1)
            anyfunc("abcd")

        with self.assertRaises(Invalid):
            anyfunc = Any(invalid_1, invalid_2)
            anyfunc("abcd")

    def test_any_should_consider_all_values_valid_unless_invalid_raised(self):
        def return_func(data):
            return data
        mocked = Mock(return_value=1)
        anyfunc = Any(return_func, mocked)

        val = anyfunc(0)
        self.assertEqual(val, 0)
        self.assertFalse(mocked.called)
        val = anyfunc(0.0)
        self.assertEqual(val, 0.0)
        self.assertFalse(mocked.called)
        val = anyfunc(None)
        self.assertEqual(val, None)
        self.assertFalse(mocked.called)
        val = anyfunc(False)
        self.assertEqual(val, False)
        self.assertFalse(mocked.called)
        val = anyfunc(Undefined)
        self.assertEqual(val, Undefined)
        self.assertFalse(mocked.called)
        invalid = Invalid("")
        val = anyfunc(invalid)
        self.assertEqual(val, invalid)
        self.assertFalse(mocked.called)


class TestAllFunction(unittest.TestCase):
    def test_all_returns_a_new_function(self):
        allfunc = All(int)
        self.assertTrue(callable(allfunc))

    def test_all_with_no_schemas_returns_the_passed_in_data(self):
        allfunc = All()
        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(Undefined), Undefined)
        self.assertEqual(allfunc("abcdefg"), "abcdefg")

    def test_all_calls_validators_until_invalid_is_raised(self):
        valid_1 = Mock(return_value=1)
        valid_2 = Mock(return_value=1)
        valid_3 = Mock(return_value=1)
        invalid = Mock(side_effect=Invalid("1"))

        allfunc = All(valid_1, valid_2, valid_3)
        allfunc(1)
        valid_1.assert_called_once_with(1)
        valid_2.assert_called_once_with(1)
        valid_3.assert_called_once_with(1)

        valid_1.reset_mock()
        valid_2.reset_mock()
        valid_3.reset_mock()
        with self.assertRaises(Invalid):
            allfunc = All(valid_1, valid_2, invalid, valid_3)
            allfunc(1)
        valid_1.assert_called_once_with(1)
        valid_2.assert_called_once_with(1)
        invalid.assert_called_once_with(1)
        self.assertFalse(valid_3.called)

    def test_all_allows_validators_to_munge_the_data(self):
        valid_1 = Mock(return_value=1)
        valid_2 = Mock(return_value=2)
        valid_3 = Mock(return_value=3)

        allfunc = All(valid_1, valid_2, valid_3)
        allfunc(0)
        valid_1.assert_called_once_with(0)
        valid_2.assert_called_once_with(1)
        valid_3.assert_called_once_with(2)

    def test_all_returns_the_value_from_the_final_validator(self):
        valid_1 = Mock(return_value=False)
        valid_2 = Mock(return_value=Undefined)
        valid_3 = Mock(return_value="abc123")

        allfunc = All(valid_1, valid_2, valid_3)
        self.assertEqual(allfunc(0), "abc123")
        allfunc = All(valid_2, valid_3, valid_1)
        self.assertFalse(allfunc(1))
        allfunc = All(valid_3, valid_1, valid_2)
        self.assertEqual(allfunc(2), Undefined)

    def test_all_should_consider_all_values_valid_unless_invalid_raised(self):
        def return_func(data):
            return data
        allfunc = All(return_func)

        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(0.0), 0.0)
        self.assertEqual(allfunc(None), None)
        self.assertEqual(allfunc(False), False)
        self.assertEqual(allfunc(Undefined), Undefined)
        invalid = Invalid("")
        self.assertEqual(allfunc(invalid), invalid)


class TestCoerceTo(unittest.TestCase):
    def test_coerce_to_returns_values_based_on_passed_in_type(self):
        c = coerce_to(int)
        self.assertEqual(c("0"), 0)
        self.assertEqual(c("1"), 1)
        self.assertEqual(c(1234), 1234)

        c = coerce_to(unicode)
        self.assertEqual(c(0), "0")
        self.assertEqual(c(False), "False")
        self.assertEqual(c("abc"), "abc")

    def test_coerce_to_raises_an_invalid_exception_on_bad_data(self):
        with self.assertRaises(Invalid) as cm:
            c = coerce_to(int)
            c("abc")
        self.assertEqual(str(cm.exception), "expected int")

        with self.assertRaises(Invalid) as cm:
            c = coerce_to(float)
            c(None)
        self.assertEqual(str(cm.exception), "expected float")

    def test_coerce_to_does_not_coerce_undefined(self):
        c = coerce_to(int)
        self.assertEqual(c(Undefined), Undefined)
        c = coerce_to(bool)
        self.assertEqual(c(Undefined), Undefined)
        c = coerce_to(unicode)
        self.assertEqual(c(Undefined), Undefined)


class TestRequireOne(unittest.TestCase):
    def test_require_one_returns_an_invalid_group_with_invalids_removed(self):
        data = {
            "a": Invalid("a"), "b": 1, "c": Invalid("c"),
            "d": Invalid("d"), "e": 2, "f": 3
        }
        req = require_one("a", "b", "d", "f")
        with self.assertRaises(Invalid) as cm:
            req(InvalidGroup([data["a"], data["c"], data["d"]], data))
        self.assertEqual(str(cm.exception), "c")
        self.assertEqual(cm.exception.data, {"b": 1, "c": data["c"], "e": 2})

    def test_require_one_returns_data_with_invalids_removed(self):
        data = {
            "a": Invalid("a"), "b": 1, "c": "abc",
            "d": Invalid("d"), "e": 2, "f": 3
        }
        req = require_one("a", "b", "d", "f")
        val = req(InvalidGroup([data["a"], data["d"]], data))
        self.assertEqual(val, {"b": 1, "c": "abc", "e": 2})

    def test_require_one_returns_data_with_data_removed(self):
        data = {"a": 0, "b": 1, "c": "abc", "d": "def", "e": 2, "f": 3}
        req = require_one("a", "b", "d", "f")
        val = req(data)
        self.assertEqual(val, {"a": 0, "c": "abc", "e": 2})


class TestRequireIf(unittest.TestCase):
    def test_require_if_returns_an_invalid_group_with_invalids_removed(self):
        data = {"a": Invalid("a"), "b": 1, "c": Invalid("c"), "d": 2}
        req = require_if("a", Mock(return_value=False))
        with self.assertRaises(Invalid) as cm:
            req(InvalidGroup([data["a"], data["c"]], data))
        self.assertEqual(str(cm.exception), "c")
        self.assertEqual(cm.exception.data, {"b": 1, "c": data["c"], "d": 2})
        data = {"a": Invalid("a"), "b": 1, "c": Invalid("c"), "d": 2}
        req = require_if("a", Mock(return_value=True))
        with self.assertRaises(Invalid) as cm:
            req(InvalidGroup([data["a"], data["c"]], data))
        self.assertEqual(str(cm.exception), "a\nc")
        self.assertEqual(
            cm.exception.data,
            {"a": data["a"], "b": 1, "c": data["c"], "d": 2})

    def test_require_one_returns_data_with_invalids_removed(self):
        data = {"a": Invalid("a"), "b": 1, "c": "abc", "d": 2}
        req = require_if("a", Mock(return_value=False))
        val = req(InvalidGroup([data["a"]], data))
        self.assertEqual(val, {"b": 1, "c": "abc", "d": 2})

    def test_require_one_returns_data_with_data_removed(self):
        data = {"a": 0, "b": 1, "c": "abc"}
        req = require_if("a", Mock(return_value=False))
        val = req(data)
        self.assertEqual(val, {"b": 1, "c": "abc"})
        data = {"a": 0, "b": 1, "c": "abc"}
        req = require_if("a", Mock(return_value=True))
        val = req(data)
        self.assertEqual(val, {"a": 0, "b": 1, "c": "abc"})


class TestWhenValidators(unittest.TestCase):
    def test_when_base_returns_invalid_when_passed_the_invalid_class(self):
        val = _when_base(None, Invalid)
        self.assertTrue(isinstance(val, Invalid))
        self.assertEqual(str(val), "A value is required")

    def test_when_base_returns_invalid_when_passed_an_invalid_instance(self):
        val = _when_base(None, Invalid("abc"))
        self.assertTrue(isinstance(val, Invalid))
        self.assertEqual(str(val), "abc")
        val = _when_base(None, InvalidGroup([Invalid("a"), Invalid("b")]))
        self.assertTrue(isinstance(val, InvalidGroup))
        self.assertEqual(str(val), "a\nb")

    def test_when_base_returns_function_value_when_passed_a_function(self):
        mocked = Mock(return_value=8)
        self.assertEqual(_when_base(None, mocked), 8)
        mocked.assert_called_once_with(None)
        mocked.reset_mock()
        self.assertEqual(_when_base("abc", mocked), 8)
        mocked.assert_called_once_with("abc")

    def test_when_base_returns_value_when_passed_a_standard_value(self):
        self.assertEqual(_when_base("abc", "def"), "def")
        self.assertEqual(_when_base(0, None), None)

    def test_when_empty_raises_stop_validation_on_falsy_values(self):
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")(0)
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")(0.0)
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")(False)
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")(None)
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")("")
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_empty("abc")(Undefined)
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_empty("def")(1), 1)
        self.assertEqual(when_empty("def")(0.01), 0.01)
        self.assertEqual(when_empty("def")(True), True)
        self.assertEqual(when_empty("def")("abc"), "abc")

    def test_when_zero_raises_stop_validation_on_zero(self):
        with self.assertRaises(StopValidation) as cm:
            when_zero("abc")(0)
        self.assertEqual(cm.exception.data, "abc")
        with self.assertRaises(StopValidation) as cm:
            when_zero("abc")(0.0)
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_zero("abc")(False), False)
        self.assertEqual(when_zero("abc")(None), None)
        self.assertEqual(when_zero("abc")(""), "")
        self.assertEqual(when_zero("abc")(Undefined), Undefined)
        self.assertEqual(when_zero("def")(1), 1)
        self.assertEqual(when_zero("def")(0.01), 0.01)
        self.assertEqual(when_zero("def")(True), True)
        self.assertEqual(when_zero("def")("abc"), "abc")

    def test_when_false_raises_stop_validation_on_false(self):
        self.assertEqual(when_false("abc")(0), 0)
        self.assertEqual(when_false("abc")(0.0), 0.0)
        with self.assertRaises(StopValidation) as cm:
            when_false("abc")(False)
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_false("abc")(None), None)
        self.assertEqual(when_false("abc")(""), "")
        self.assertEqual(when_false("abc")(Undefined), Undefined)
        self.assertEqual(when_false("def")(1), 1)
        self.assertEqual(when_false("def")(0.01), 0.01)
        self.assertEqual(when_false("def")(True), True)
        self.assertEqual(when_false("def")("abc"), "abc")

    def test_when_none_raises_stop_validation_on_none(self):
        self.assertEqual(when_none("abc")(0), 0)
        self.assertEqual(when_none("abc")(0.0), 0.0)
        self.assertEqual(when_none("abc")(False), False)
        with self.assertRaises(StopValidation) as cm:
            when_none("abc")(None)
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_none("abc")(""), "")
        self.assertEqual(when_none("abc")(Undefined), Undefined)
        self.assertEqual(when_none("def")(1), 1)
        self.assertEqual(when_none("def")(0.01), 0.01)
        self.assertEqual(when_none("def")(True), True)
        self.assertEqual(when_none("def")("abc"), "abc")

    def test_when_empty_str_raises_stop_validation_on_empty_string(self):
        self.assertEqual(when_empty_str("abc")(0), 0)
        self.assertEqual(when_empty_str("abc")(0.0), 0.0)
        self.assertEqual(when_empty_str("abc")(False), False)
        self.assertEqual(when_empty_str("abc")(None), None)
        with self.assertRaises(StopValidation) as cm:
            when_empty_str("abc")("")
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_empty_str("abc")(Undefined), Undefined)
        self.assertEqual(when_empty_str("def")(1), 1)
        self.assertEqual(when_empty_str("def")(0.01), 0.01)
        self.assertEqual(when_empty_str("def")(True), True)
        self.assertEqual(when_empty_str("def")("abc"), "abc")

    def test_when_undefined_raises_stop_validation_on_undefined(self):
        self.assertEqual(when_undefined("abc")(0), 0)
        self.assertEqual(when_undefined("abc")(0.0), 0.0)
        self.assertEqual(when_undefined("abc")(False), False)
        self.assertEqual(when_undefined("abc")(None), None)
        self.assertEqual(when_undefined("abc")(""), "")
        with self.assertRaises(StopValidation) as cm:
            when_undefined("abc")(Undefined)
        self.assertEqual(cm.exception.data, "abc")
        self.assertEqual(when_undefined("def")(1), 1)
        self.assertEqual(when_undefined("def")(0.01), 0.01)
        self.assertEqual(when_undefined("def")(True), True)
        self.assertEqual(when_undefined("def")("abc"), "abc")


class TestIntegration(unittest.TestCase):
    def test_basic_integration_test(self):
        s = Schema({
            "abc": All(coerce_to(str), when_empty(Invalid)),
            "def": All(int, when_empty(Invalid))
        })
        with self.assertRaises(InvalidGroup) as cm:
            s({})
        self.assertEqual(
            map(str, cm.exception.errors),
            [
                "A value is required @ data[abc]",
                "A value is required @ data[def]"
            ],
        )
        a = s({"abc": 1, "def": 2})
        self.assertEqual(a, {"abc": "1", "def": 2})

        s = Schema(All({
            "abc": coerce_to(str),
            "def": int
        }))
        with self.assertRaises(InvalidGroup) as cm:
            s({"abc": 1, "def": "abc"})
        self.assertEqual(
            map(str, cm.exception.errors),
            [
                "Expected int @ data[def]"
            ]
        )

        s = Schema(All({
            "abc": All(coerce_to(str), when_empty(Invalid)),
            "def": All(int, when_empty(Invalid))
        }))
        with self.assertRaises(InvalidGroup) as cm:
            s({})
        self.assertEqual(
            map(str, cm.exception.errors),
            [
                "A value is required @ data[abc]",
                "A value is required @ data[def]"
            ],
        )

    def test_more_advanced_integration_test(self):
        def percents_add_to_100(data):
            total = 0
            for project in data:
                total += project["percentage"]
            if total != 100:
                raise Invalid("the percentages must add up to 100")
            return data

        def check_required_by(data):
            return data["required_by_type"] == "later"
        s = Schema(
            Chain(
                {
                    "description": All(str, when_empty(Invalid)),
                    "justification": All(str, when_empty(Invalid)),
                    "is_tech_purchase": All(bool, when_empty(False)),
                    "projects": All(
                        [{
                            "id": All(int, when_empty(Undefined)),
                            "project_id": All(int, when_empty(Invalid)),
                            "percentage": All(
                                int, in_range(1, 100), when_empty(Invalid))
                        }],
                        percents_add_to_100
                    ),
                    "vendor": All(str, when_empty(Invalid)),
                    "vendor_id": All(int, when_empty(Invalid)),
                    "required_by_type": All(str, in_list(["now", "later"])),
                    "date_required_by": All(int, when_empty(Invalid))
                },
                require_one("vendor_id", "vendor"),
                require_if("date_required_by", check_required_by)))
        data = {
            "description": "abc",
            "justification": "def",
            "projects": [
                {"project_id": 4, "percentage": 10},
                {"id": 2, "project_id": 5, "percentage": 90}
            ],
            "vendor": "ABC co.",
            "required_by_type": "later",
            "date_required_by": 1234
        }
        val = s(data)
        self.assertEqual(
            val, {
                "description": "abc",
                "justification": "def",
                "is_tech_purchase": False,
                "projects": [
                    {"project_id": 4, "percentage": 10},
                    {"id": 2, "project_id": 5, "percentage": 90}
                ],
                "vendor": "ABC co.",
                "required_by_type": "later",
                "date_required_by": 1234
            })

        # with self.assertRaises(InvalidGroup) as cm:
        #     s({
        #         "description": "abc",
        #         "is_tech_purchase"
        #         })
