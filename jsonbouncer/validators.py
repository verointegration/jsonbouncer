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
