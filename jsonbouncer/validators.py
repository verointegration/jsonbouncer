# -*- coding: utf-8 -*-
"""Validators that can be used in Schemas.
"""

from __future__ import division, unicode_literals

from jsonbouncer import Invalid, Undefined


def Coerce(func):
    def inner(data):
        if data is Undefined:
            return Undefined
        try:
            return func(data)
        except (ValueError, TypeError):
            raise Invalid("expected {0}".format(func.__name__))
    return inner


def Range(minimum=None, maximum=None):
    def inner(data):
        if minimum is not None and data < minimum:
            raise Invalid("must be at least {0}".format(minimum))
        if maximum is not None and data > maximum:
            raise Invalid("must be no more than {0}".format(maximum))
        return data
    return inner


def Minimum(value, inclusive=True):
    if not inclusive:
        value += 1
    return Range(value)


def Maximum(value, inclusive=True):
    if not inclusive:
        value -= 1
    return Range(None, value)


def InList(allowed):
    def inner(data):
        if data not in allowed:
            raise Invalid("not in list of valid values")
        return data
    return inner


def RequireOne(*fields):
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


def RequireIf(field, func):
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
