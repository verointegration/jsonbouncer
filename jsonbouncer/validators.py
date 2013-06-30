# -*- coding: utf-8 -*-
"""Validators that can be used in Schemas.
"""

from __future__ import division, unicode_literals

from jsonbouncer import Invalid, StopValidation, Undefined


def coerce_to(func):
    def inner(data):
        if data is Undefined:
            return Undefined
        try:
            return func(data)
        except (ValueError, TypeError):
            raise Invalid("expected {0}".format(func.__name__))
    return inner


def in_range(minimum=None, maximum=None):
    def inner(data):
        if minimum is not None and data < minimum:
            raise Invalid("must be at least {0}".format(minimum))
        if maximum is not None and data > maximum:
            raise Invalid("must be no more than {0}".format(maximum))
        return data
    return inner


def minimum(value, inclusive=True):
    if not inclusive:
        value += 1
    return in_range(value)


def maximum(value, inclusive=True):
    if not inclusive:
        value -= 1
    return in_range(None, value)


def in_list(allowed):
    def inner(data):
        if data not in allowed:
            raise Invalid("not in list of valid values")
        return data
    return inner


def require_one(*fields):
    def inner(data):
        working_data = data
        is_invalid = False
        if isinstance(data, Invalid):
            working_data = data.data
            is_invalid = True
        if not isinstance(working_data, dict):
            return Invalid("Expected an object")
        valid_field = None
        for field in fields:
            if not isinstance(working_data[field], Invalid):
                valid_field = field
                break
        if valid_field:
            for field in fields:
                if field == valid_field:
                    continue
                if is_invalid and isinstance(working_data[field], Invalid):
                    data.errors.remove(working_data[field])
                del working_data[field]
        if is_invalid and data.errors:
            data.data = working_data
            raise data
        return working_data
    return inner


def require_if(field, func):
    def inner(data):
        working_data = data
        is_invalid = False
        if isinstance(data, Invalid):
            working_data = data.data
            is_invalid = True
        if not isinstance(working_data, dict):
            return Invalid("Expected an object")
        is_required = func(working_data)
        if not is_required:
            if is_invalid and isinstance(working_data[field], Invalid):
                data.errors.remove(working_data[field])
            del working_data[field]
        if is_invalid and data.errors:
            data.data = working_data
            raise data
        return working_data
    return inner


def when_empty(func):
    def inner(data):
        if not bool(data):
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_zero(func):
    def inner(data):
        if data == 0 and type(data) != bool:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_false(func):
    def inner(data):
        if data is False:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_none(func):
    def inner(data):
        if data is None:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_empty_str(func):
    def inner(data):
        if data == "":
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_undefined(func):
    def inner(data):
        if data is Undefined:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def _when_base(data, func):
    if func == Invalid:
        return Invalid("A value is required")
    if isinstance(func, Invalid):
        return func
    if callable(func):
        return func(data)
    return func
