#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2016 Freie Universität Berlin
#
# This file is subject to the terms and conditions of the GNU Lesser
# General Public License v2.1. See the file LICENSE in the top level
# directory for more details.

from __future__ import print_function
import pexpect
from subprocess import check_output, STDOUT, CalledProcessError
import os, sys
import shlex

MOD_PATH = os.path.dirname(__file__) + ''
RIOT_BASE = os.path.realpath(os.path.join(MOD_PATH ,'../../../..'))
TESTS_BASE = os.path.join(RIOT_BASE, 'tests')

DEFAULT_TIMEOUT = 60

class DefaultBuildStrategy(object):
    def __init__(self, boards):
        self.boards = boards

    def build(self, name):
        for board in self.boards:
            env = os.environ.copy()
            env.update(board.to_env())
            cmd = 'make -C %s -B clean flash' % os.path.join(TESTS_BASE, name)
            print('(%s) ' % cmd, end='')
            sys.stdout.flush()
            try:
                out = check_output(shlex.split(cmd), env=env,
                                   universal_newlines=True, stderr=STDOUT)
                return True
            except CalledProcessError as e:
                print(e.output)
                return False

class DefaultTestStrategy(object):
    def __init__(self, boards):
        self.boards = boards

    def test(self, name):
        for board in self.boards:
            env = os.environ.copy()
            env.update(board.to_env())
            cmd = 'make -C %s term' % os.path.join(TESTS_BASE, name)
            print('(%s) ' % cmd, end='')
            sys.stdout.flush()
            child  = pexpect.spawn(cmd, env=env, timeout=DEFAULT_TIMEOUT)
            try:
                child.expect("TEST: SUCCESS")
            except pexpect.exceptions.TIMEOUT as e:
                print(e)
                return False
            finally:
                child.close()
        return True
