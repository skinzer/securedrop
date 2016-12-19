#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest

import manage

ABS_MODULE_PATH = os.path.dirname(os.path.abspath(__file__))

class TestManagePy(unittest.TestCase):

    def test_parse_args(self):
        # just test that the arg parser is stable
        manage.get_args()

    def test_all_unit_tests_are_returned(self):
        output = manage._get_test_module_dict("unit")
        for file in os.listdir(ABS_MODULE_PATH):
            file in output.values()

    def test_all_functional_tests_are_returned(self):
        output = manage._get_test_module_dict("functional")
        for file in os.listdir(os.path.join(ABS_MODULE_PATH, "functional")):
            file in output.values()
