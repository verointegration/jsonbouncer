# -*- coding: utf-8 -*-
"""Validators that can be used in Schemas.
"""

from __future__ import division, unicode_literals
from functools import wraps

from jsonbouncer import (
    InvalidBase, Invalid, InvalidGroup, StopValidation, Undefined)


def coerce_to(func):
    @wraps(coerce_to)
    def inner(data):
        if data is Undefined:
            return Undefined
        try:
            return func(data)
        except (ValueError, TypeError):
            raise Invalid("Expected {0}".format(func.__name__))
    return inner


def in_range(minimum=None, maximum=None):
    @wraps(in_range)
    def inner(data):
        if data is Undefined:
            return Undefined
        if minimum is not None and data < minimum:
            raise Invalid("Must be at least {0}".format(minimum))
        if maximum is not None and data > maximum:
            raise Invalid("Must be no more than {0}".format(maximum))
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
    @wraps(in_list)
    def inner(data):
        if data is Undefined:
            return Undefined
        if data not in allowed:
            raise Invalid("Not in list of valid values")
        return data
    return inner


def require_one(*fields):
    @wraps(require_one)
    def inner(data):
        working_data = data
        is_invalid = False
        if isinstance(data, InvalidGroup):
            working_data = data.data
            is_invalid = True
        if not isinstance(working_data, dict):
            raise Invalid("Expected an object")
        valid_field = None
        for field in fields:
            if not isinstance(working_data[field], InvalidBase):
                valid_field = field
                break
        if valid_field:
            for field in fields:
                if field == valid_field:
                    continue
                if is_invalid and isinstance(working_data[field], InvalidBase):
                    data.errors.remove(working_data[field])
                del working_data[field]
        if is_invalid and data.errors:
            data.data = working_data
            raise data
        return working_data
    return inner


def require_if(field, func):
    @wraps(require_if)
    def inner(data):
        working_data = data
        is_invalid = False
        if isinstance(data, InvalidBase):
            working_data = data.data
            is_invalid = True
        if not isinstance(working_data, dict):
            raise Invalid("Expected an object")
        is_required = func(working_data)
        if not is_required:
            if is_invalid and isinstance(working_data[field], InvalidBase):
                data.errors.remove(working_data[field])
            del working_data[field]
        if is_invalid and data.errors:
            data.data = working_data
            raise data
        return working_data
    return inner


def when_empty(func):
    @wraps(when_empty)
    def inner(data):
        if not bool(data):
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_zero(func):
    @wraps(when_zero)
    def inner(data):
        if data == 0 and type(data) != bool:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_false(func):
    @wraps(when_false)
    def inner(data):
        if data is False:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_none(func):
    @wraps(when_none)
    def inner(data):
        if data is None:
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_empty_str(func):
    @wraps(when_empty_str)
    def inner(data):
        if data == "":
            raise StopValidation(_when_base(data, func))
        return data
    return inner


def when_undefined(func):
    @wraps(when_undefined)
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
