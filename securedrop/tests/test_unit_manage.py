#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest

import fnmatch
import manage

ABS_MODULE_PATH = os.path.dirname(os.path.abspath(__file__))

class TestManagePy(unittest.TestCase):

    def test_parse_args(self):
        # Simple test to make sure arg_parser is stable
        manage.get_args()

    def test_get_test_module_dict_functional(self):
        output = manage._get_test_module_dict('functional')
        # All test modules should be present
        for file in os.listdir(os.path.join(ABS_MODULE_PATH, "functional")):
            if fnmatch.fnmatch(file, 'test*.py'):
                self.assertIn(os.path.join(ABS_MODULE_PATH, 'functional',
                                           file),
                              output.values())
        # The test modules short names should not contain path, extension, or
        # other unecessary text
        for test in list(output):
            self.assertNotRegexpMatches(ABS_MODULE_PATH, test)
            self.assertNotRegexpMatches('test_', test)
            self.assertNotRegexpMatches('py', test)
        # The short name (key) should be a substring of the test's path
        for test, test_path in output.items():
            self.assertRegexpMatches(test_path, test)

    def test_get_test_module_dict_unit(self):
        output = manage._get_test_module_dict('unit')
        # All test modules should be present
        for file in os.listdir(ABS_MODULE_PATH):
            if fnmatch.fnmatch(file, 'test*.py'):
                self.assertIn(os.path.join(ABS_MODULE_PATH, file),
                              output.values())
        # The test modules short names should not contain path, extension, or
        # other unecessary text
        for test in list(output):
            self.assertNotRegexpMatches(ABS_MODULE_PATH, test)
            # For app code modules for which there are multiple corresponding
            # unit test modules, one will be prefixed by 'test'.
            self.assertNotRegexpMatches('test_unit', test)
            self.assertNotRegexpMatches('py', test)
        # The short name (key) should be a substring of the test's path
        for test, test_path in output.items():
            self.assertRegexpMatches(test_path, test)
