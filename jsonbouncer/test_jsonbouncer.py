# -*- coding: utf-8 -*-
# pylint: disable-all
from __future__ import division, unicode_literals

import math
import unittest
from mock import Mock, call, patch

from jsonbouncer import (
    Schema, Invalid, InvalidGroup, Undefined, SchemaError, Any, All)


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

    def test_creating_an_invalid_exception_saves_the_passed_in_path(self):
        instance = Invalid("")
        self.assertEqual(instance.path, [])
        instance = Invalid("", [1, "b", 3])
        self.assertEqual(instance.path, [1, "b", 3])

    def test_invalid_exception_prints_path_if_given(self):
        instance = Invalid("Invalid message")
        self.assertEqual(str(instance), "Invalid message")
        instance = Invalid("Invalid message", [1, "b", 3])
        self.assertEqual(str(instance), "Invalid message @ data[1][b][3]")


class TestInvalidGroup(unittest.TestCase):
    def test_invalid_group_returns_the_first_error_message_as_its_str(self):
        instance = InvalidGroup([Invalid("a"), Invalid("b")])
        self.assertEqual(str(instance), "a")


class TestSchema(unittest.TestCase):
    def test_creating_a_schema_saves_the_passed_in_schema(self):
        schema = {"a": "b", "k": "l", "y": 3}
        instance = Schema(schema)
        self.assertEqual(instance.schema, {"a": "b", "k": "l", "y": 3})

    def test_calling_a_schema_calls_validate(self):
        mocked = Mock(return_value=(1, []))
        with patch.object(Schema, "_validate", mocked):
            instance = Schema({"a": int})
            instance({"a": 1})
            mocked.assert_called_once_with({"a": int}, {"a": 1}, [])

    def test_calling_a_schema_returns_data_when_data_is_valid(self):
        mocked = Mock(return_value=(1, []))
        with patch.object(Schema, "_validate", mocked):
            instance = Schema({"a": int})
            retval = instance({"a": 1})
            self.assertEqual(retval, 1)

    def test_calling_a_schema_raises_invalid_group_when_data_is_invalid(self):
        mocked = Mock(return_value=(1, [1, 2, 3]))
        with patch.object(Schema, "_validate", mocked):
            with self.assertRaises(InvalidGroup) as cm:
                instance = Schema({"a": int})
                instance({"a": 1})
            self.assertEqual(cm.exception.errors, [1, 2, 3])

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

    def test_validate_type_returns_value_on_valid_data(self):
        data, errors = Schema._validate_type(unicode, "", [])
        self.assertEqual(data, "")
        self.assertEqual(errors, [])
        data, errors = Schema._validate_type(int, 0, [])
        self.assertEqual(data, 0)
        self.assertEqual(errors, [])
        data, errors = Schema._validate_type(bool, False, [])
        self.assertEqual(data, False)
        self.assertEqual(errors, [])

    def test_validate_type_returns_error_and_error_list_on_invalid_data(self):
        with patch("jsonbouncer.jsonbouncer.Invalid") as mocked:
            data, errors = Schema._validate_type(unicode, 1, [])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            data, errors = Schema._validate_type(int, "abc", [])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            data, errors = Schema._validate_type(bool, None, [])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])

    def test_validate_type_errors_have_message_and_path_filled_in(self):
        with patch("jsonbouncer.jsonbouncer.Invalid") as mocked:
            Schema._validate_type(unicode, 1, [])
            mocked.assert_called_once_with("Expected unicode", [])
            mocked.reset_mock()
            Schema._validate_type(int, None, [1])
            mocked.assert_called_once_with("Expected int", [1])
            mocked.reset_mock()
            Schema._validate_type(bool, "", ["a", 0, "b"])
            mocked.assert_called_once_with("Expected bool", ["a", 0, "b"])

    def test_validate_dict_returns_invalid_if_not_given_a_dictionary(self):
        with patch("jsonbouncer.jsonbouncer.Invalid") as mocked:
            data, errors = Schema._validate_dict({}, [], [])
            mocked.assert_called_once_with("Expected an object", [])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            mocked.reset_mock()
            data, errors = Schema._validate_dict({}, Undefined, [1])
            mocked.assert_called_once_with("Expected an object", [1])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            mocked.reset_mock()
            data, errors = Schema._validate_dict({}, None, ["a", "b"])
            mocked.assert_called_once_with("Expected an object", ["a", "b"])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])

    def test_validate_dict_returns_all_data_if_schema_is_empty(self):
        data, errors = Schema._validate_dict({}, {"a": 1, "b": None}, [])
        self.assertEqual(data, {"a": 1, "b": None})
        self.assertEqual(errors, [])
        data, errors = Schema._validate_dict({}, {"a": None}, [])
        self.assertEqual(data, {"a": None})
        self.assertEqual(errors, [])

    def test_validate_dict_calls_validate_once_for_each_key(self):
        mocked = Mock(return_value=({}, []))
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
        mocked = Mock(return_value=({}, []))
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

    def test_validate_dict_sets_undefined_if_a_value_isnt_in_data(self):
        mocked = Mock(return_value=({}, []))
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

    def test_validate_dict_returns_values_from_validation(self):
        def mock_return(schema, data, path):
            return data, []

        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = {"a": int, "b": int, "c": int, "d": int}
            original_data = {"a": 1, "c": 2, "d": 3}
            expected_data = {"a": 1, "b": Undefined, "c": 2, "d": 3}
            val, errors = Schema._validate_dict(schema, original_data, [])
            self.assertEqual(val, expected_data)
            self.assertEqual(errors, [])

    def test_validate_dict_appends_and_returns_errors_from_validation(self):
        def mock_return(schema, data, path):
            if data != Undefined and data > 2:
                return "err{0}".format(data), [data]
            return data, []

        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = {"a": int, "b": int, "c": int, "d": int}
            original_data = {"a": 1, "c": 3, "d": 4}
            expected_data = {"a": 1, "b": Undefined, "c": "err3", "d": "err4"}
            val, errors = Schema._validate_dict(schema, original_data, [])
            self.assertEqual(val, expected_data)
            self.assertEqual(errors, [3, 4])

    def test_validate_list_returns_invalid_if_not_given_a_list(self):
        with patch("jsonbouncer.jsonbouncer.Invalid") as mocked:
            data, errors = Schema._validate_list([], {}, [])
            mocked.assert_called_once_with("Expected a list", [])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            mocked.reset_mock()
            data, errors = Schema._validate_list([], Undefined, [1])
            mocked.assert_called_once_with("Expected a list", [1])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])
            mocked.reset_mock()
            data, errors = Schema._validate_list([], None, ["a", "b"])
            mocked.assert_called_once_with("Expected a list", ["a", "b"])
            self.assertEqual(data, mocked())
            self.assertEqual(errors, [mocked()])

    def test_validate_list_returns_unmodified_data_when_schema_is_empty(self):
        data, errors = Schema._validate_list([], [1, 2, 3], [])
        self.assertEqual(data, [1, 2, 3])
        self.assertEqual(errors, [])
        data, errors = Schema._validate_list([], ["a", [], False], [])
        self.assertEqual(data, ["a", [], False])
        self.assertEqual(errors, [])

    def test_validate_list_calls_validate_for_each_data_entry(self):
        mocked = Mock(return_value=(1, []))
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
                error = Invalid("")
                return error, [error]
            return data, []

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
            Schema._validate_list([int, unicode], [None], [])
            mocked.assert_has_calls([
                call(int, None, [0]),
                call(unicode, None, [0])
            ])

    def test_validate_list_calls_validate_for_each_schema_data_combo(self):
        def mock_return(schema, data, path):
            if not isinstance(data, schema):
                error = Invalid("")
                return error, [error]
            return data, []

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
        mocked = Mock(return_value=(1, []))
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

    def test_validate_list_returns_values_from_validation(self):
        def mock_return(schema, data, path):
            return data, []

        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = [unicode, int]
            original_data = [1, "a", 2, 3, "b"]
            expected_data = [1, "a", 2, 3, "b"]
            val, errors = Schema._validate_list(schema, original_data, [])
            self.assertEqual(val, expected_data)
            self.assertEqual(errors, [])

    def test_validate_list_appends_and_returns_errors_from_validation(self):
        def mock_return(schema, data, path):
            if isinstance(data, int) and data > 2:
                return "err{0}".format(data), [data]
            return data, []

        mocked = Mock(side_effect=mock_return)
        with patch.object(Schema, "_validate", mocked):
            schema = [unicode, int]
            original_data = [1, "a", 3, "b", 4, 2]
            expected_data = [1, "a", "err3", "b", "err4", 2]
            val, errors = Schema._validate_list(schema, original_data, [])
            self.assertEqual(val, expected_data)
            self.assertEqual(errors, [3, 4])

    def test_validate_function_calls_the_function(self):
        func = Mock()
        Schema._validate_function(func, "abc", [])
        func.assert_called_once_with("abc")

    def test_validate_function_returns_the_value_from_the_function(self):
        func = Mock(return_value=1)
        val, errors = Schema._validate_function(func, "abc", [])
        self.assertEqual(val, 1)
        self.assertEqual(errors, [])

    def test_validate_function_catches_and_returns_invalid_exceptions(self):
        invalid = Invalid("abc")
        func = Mock(side_effect=invalid)
        val, errors = Schema._validate_function(func, "abc", [])
        self.assertEqual(val.message, "abc")
        self.assertEqual(errors[0].message, "abc")

    def test_validate_function_catches_value_errors_and_returns_invalid(self):
        func = Mock(side_effect=ValueError)
        val, errors = Schema._validate_function(func, "abc", [])
        self.assertEqual(val.message, "Invalid value given")

    def test_validate_function_prepends_the_path_to_any_invalid_raised(self):
        invalid = Invalid("abc")
        func = Mock(side_effect=invalid)
        val, errors = Schema._validate_function(func, "abc", ["a"])
        self.assertEqual(val.path, ["a"])
        invalid = Invalid("abc", ["b"])
        func = Mock(side_effect=invalid)
        val, errors = Schema._validate_function(func, "abc", ["a"])
        self.assertEqual(val.path, ["a", "b"])
        func = Mock(side_effect=ValueError)
        val, errors = Schema._validate_function(func, "abc", ["a"])
        self.assertEqual(val.path, ["a"])


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
        anyfunc("abcd")
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

    def test_any_applies_the_when_empty_argument_on_an_empty_value(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_empty="abcdef")

        self.assertEqual(anyfunc(0), "abcdef")
        self.assertEqual(anyfunc(0.0), "abcdef")
        self.assertEqual(anyfunc(False), "abcdef")
        self.assertEqual(anyfunc(None), "abcdef")
        self.assertEqual(anyfunc(""), "abcdef")
        self.assertEqual(anyfunc(Undefined), "abcdef")

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        anyfunc = Any(return_func, when_empty=mocked)

        self.assertEqual(anyfunc(0), "abcdef")
        mocked.assert_called_once_with(0)
        mocked.reset_mock()
        self.assertEqual(anyfunc(0.0), "abcdef")
        mocked.assert_called_once_with(0.0)
        mocked.reset_mock()
        self.assertEqual(anyfunc(False), "abcdef")
        mocked.assert_called_once_with(False)
        mocked.reset_mock()
        self.assertEqual(anyfunc(None), "abcdef")
        mocked.assert_called_once_with(None)
        mocked.reset_mock()
        self.assertEqual(anyfunc(""), "abcdef")
        mocked.assert_called_once_with("")
        mocked.reset_mock()
        self.assertEqual(anyfunc(Undefined), "abcdef")
        mocked.assert_called_once_with(Undefined)
        mocked.reset_mock()

    def test_any_applies_the_when_zero_argument_on_a_zero_value(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_zero="abcdef")

        self.assertEqual(anyfunc(0), "abcdef")
        self.assertEqual(anyfunc(0.0), "abcdef")
        self.assertEqual(anyfunc(False), False)
        self.assertEqual(anyfunc(None), None)
        self.assertEqual(anyfunc(""), "")
        self.assertEqual(anyfunc(Undefined), Undefined)

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        anyfunc = Any(return_func, when_zero=mocked)

        self.assertEqual(anyfunc(0), "abcdef")
        mocked.assert_called_once_with(0)
        mocked.reset_mock()
        self.assertEqual(anyfunc(0.0), "abcdef")
        mocked.assert_called_once_with(0.0)

    def test_any_applies_the_when_none_argument_on_a_none_value(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_none="abcdef")

        self.assertEqual(anyfunc(0), 0)
        self.assertEqual(anyfunc(0.0), 0.0)
        self.assertEqual(anyfunc(False), False)
        self.assertEqual(anyfunc(None), "abcdef")
        self.assertEqual(anyfunc(""), "")
        self.assertEqual(anyfunc(Undefined), Undefined)

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        anyfunc = Any(return_func, when_none=mocked)

        self.assertEqual(anyfunc(None), "abcdef")
        mocked.assert_called_once_with(None)

    def test_any_applies_the_when_false_argument_on_a_false_value(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_false="abcdef")

        self.assertEqual(anyfunc(0), 0)
        self.assertEqual(anyfunc(0.0), 0.0)
        self.assertEqual(anyfunc(False), "abcdef")
        self.assertEqual(anyfunc(None), None)
        self.assertEqual(anyfunc(""), "")
        self.assertEqual(anyfunc(Undefined), Undefined)

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        anyfunc = Any(return_func, when_false=mocked)

        self.assertEqual(anyfunc(False), "abcdef")
        mocked.assert_called_once_with(False)

    def test_any_applies_the_when_empty_str_argument_on_an_empty_string(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_empty_str=8)

        self.assertEqual(anyfunc(0), 0)
        self.assertEqual(anyfunc(0.0), 0.0)
        self.assertEqual(anyfunc(False), False)
        self.assertEqual(anyfunc(None), None)
        self.assertEqual(anyfunc(""), 8)
        self.assertEqual(anyfunc(Undefined), Undefined)

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value=8)
        anyfunc = Any(return_func, when_empty_str=mocked)

        self.assertEqual(anyfunc(""), 8)
        mocked.assert_called_once_with("")

    def test_any_applies_the_when_undefined_arugment_on_an_undefined(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_undefined="abcdef")

        self.assertEqual(anyfunc(0), 0)
        self.assertEqual(anyfunc(0.0), 0.0)
        self.assertEqual(anyfunc(False), False)
        self.assertEqual(anyfunc(None), None)
        self.assertEqual(anyfunc(""), "")
        self.assertEqual(anyfunc(Undefined), "abcdef")

        self.assertEqual(anyfunc(1), 1)
        self.assertEqual(anyfunc(0.01), 0.01)
        self.assertEqual(anyfunc(True), True)
        self.assertEqual(anyfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        anyfunc = Any(return_func, when_undefined=mocked)

        self.assertEqual(anyfunc(Undefined), "abcdef")
        mocked.assert_called_once_with(Undefined)

    def test_any_doesnt_apply_when_empty_if_a_more_specific_one_exists(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_empty=1, when_zero=2)
        self.assertEqual(anyfunc(0), 2)
        anyfunc = Any(return_func, when_empty=1, when_false=2)
        self.assertEqual(anyfunc(False), 2)
        anyfunc = Any(return_func, when_empty=1, when_none=2)
        self.assertEqual(anyfunc(None), 2)
        anyfunc = Any(return_func, when_empty=1, when_empty_str=2)
        self.assertEqual(anyfunc(""), 2)
        anyfunc = Any(return_func, when_empty=1, when_undefined=2)
        self.assertEqual(anyfunc(Undefined), 2)

    def test_any_raises_an_invalid_instance_if_a_when_is_set_to_invalid(self):
        def return_func(data):
            return data
        anyfunc = Any(return_func, when_empty=Invalid("abcdef"))
        with self.assertRaises(Invalid) as cm:
            anyfunc(0)
        self.assertEqual(cm.exception.message, "abcdef")
        anyfunc = Any(return_func, when_empty=Invalid)
        with self.assertRaises(Invalid) as cm:
            anyfunc(0)
        self.assertEqual(cm.exception.message, "A value is required")


class TestAllFunction(unittest.TestCase):
    def test_all_returns_a_new_function(self):
        allfunc = All(int)
        self.assertTrue(callable(allfunc))

    def test_all_with_no_schemas_returns_the_passed_in_data(self):
        allfunc = All()
        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(Undefined), Undefined)
        self.assertEqual(allfunc("abcdefg"), "abcdefg")
        allfunc = All(when_empty=8)
        self.assertEqual(allfunc(0), 8)

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

    def test_all_applies_the_when_empty_argument_on_an_empty_value(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_empty="abcdef")

        self.assertEqual(allfunc(0), "abcdef")
        self.assertEqual(allfunc(0.0), "abcdef")
        self.assertEqual(allfunc(False), "abcdef")
        self.assertEqual(allfunc(None), "abcdef")
        self.assertEqual(allfunc(""), "abcdef")
        self.assertEqual(allfunc(Undefined), "abcdef")

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        allfunc = All(return_func, when_empty=mocked)

        self.assertEqual(allfunc(0), "abcdef")
        mocked.assert_called_once_with(0)
        mocked.reset_mock()
        self.assertEqual(allfunc(0.0), "abcdef")
        mocked.assert_called_once_with(0.0)
        mocked.reset_mock()
        self.assertEqual(allfunc(False), "abcdef")
        mocked.assert_called_once_with(False)
        mocked.reset_mock()
        self.assertEqual(allfunc(None), "abcdef")
        mocked.assert_called_once_with(None)
        mocked.reset_mock()
        self.assertEqual(allfunc(""), "abcdef")
        mocked.assert_called_once_with("")
        mocked.reset_mock()
        self.assertEqual(allfunc(Undefined), "abcdef")
        mocked.assert_called_once_with(Undefined)
        mocked.reset_mock()

    def test_all_applies_the_when_zero_argument_on_a_zero_value(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_zero="abcdef")

        self.assertEqual(allfunc(0), "abcdef")
        self.assertEqual(allfunc(0.0), "abcdef")
        self.assertEqual(allfunc(False), False)
        self.assertEqual(allfunc(None), None)
        self.assertEqual(allfunc(""), "")
        self.assertEqual(allfunc(Undefined), Undefined)

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        allfunc = All(return_func, when_zero=mocked)

        self.assertEqual(allfunc(0), "abcdef")
        mocked.assert_called_once_with(0)
        mocked.reset_mock()
        self.assertEqual(allfunc(0.0), "abcdef")
        mocked.assert_called_once_with(0.0)

    def test_all_applies_the_when_none_argument_on_a_none_value(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_none="abcdef")

        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(0.0), 0.0)
        self.assertEqual(allfunc(False), False)
        self.assertEqual(allfunc(None), "abcdef")
        self.assertEqual(allfunc(""), "")
        self.assertEqual(allfunc(Undefined), Undefined)

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        allfunc = All(return_func, when_none=mocked)

        self.assertEqual(allfunc(None), "abcdef")
        mocked.assert_called_once_with(None)

    def test_all_applies_the_when_false_argument_on_a_false_value(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_false="abcdef")

        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(0.0), 0.0)
        self.assertEqual(allfunc(False), "abcdef")
        self.assertEqual(allfunc(None), None)
        self.assertEqual(allfunc(""), "")
        self.assertEqual(allfunc(Undefined), Undefined)

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        allfunc = All(return_func, when_false=mocked)

        self.assertEqual(allfunc(False), "abcdef")
        mocked.assert_called_once_with(False)

    def test_all_applies_the_when_empty_str_argument_on_an_empty_string(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_empty_str=8)

        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(0.0), 0.0)
        self.assertEqual(allfunc(False), False)
        self.assertEqual(allfunc(None), None)
        self.assertEqual(allfunc(""), 8)
        self.assertEqual(allfunc(Undefined), Undefined)

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value=8)
        allfunc = All(return_func, when_empty_str=mocked)

        self.assertEqual(allfunc(""), 8)
        mocked.assert_called_once_with("")

    def test_all_applies_the_when_undefined_arugment_on_an_undefined(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_undefined="abcdef")

        self.assertEqual(allfunc(0), 0)
        self.assertEqual(allfunc(0.0), 0.0)
        self.assertEqual(allfunc(False), False)
        self.assertEqual(allfunc(None), None)
        self.assertEqual(allfunc(""), "")
        self.assertEqual(allfunc(Undefined), "abcdef")

        self.assertEqual(allfunc(1), 1)
        self.assertEqual(allfunc(0.01), 0.01)
        self.assertEqual(allfunc(True), True)
        self.assertEqual(allfunc("abc"), "abc")

        mocked = Mock(return_value="abcdef")
        allfunc = All(return_func, when_undefined=mocked)

        self.assertEqual(allfunc(Undefined), "abcdef")
        mocked.assert_called_once_with(Undefined)

    def test_all_doesnt_apply_when_empty_if_a_more_specific_one_exists(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_empty=1, when_zero=2)
        self.assertEqual(allfunc(0), 2)
        allfunc = All(return_func, when_empty=1, when_false=2)
        self.assertEqual(allfunc(False), 2)
        allfunc = All(return_func, when_empty=1, when_none=2)
        self.assertEqual(allfunc(None), 2)
        allfunc = All(return_func, when_empty=1, when_empty_str=2)
        self.assertEqual(allfunc(""), 2)
        allfunc = All(return_func, when_empty=1, when_undefined=2)
        self.assertEqual(allfunc(Undefined), 2)

    def test_all_raises_an_invalid_instance_if_a_when_is_set_to_invalid(self):
        def return_func(data):
            return data
        allfunc = All(return_func, when_empty=Invalid("abcdef"))
        with self.assertRaises(Invalid) as cm:
            allfunc(0)
        self.assertEqual(cm.exception.message, "abcdef")
        allfunc = All(return_func, when_empty=Invalid)
        with self.assertRaises(Invalid) as cm:
            allfunc(0)
        self.assertEqual(cm.exception.message, "A value is required")
