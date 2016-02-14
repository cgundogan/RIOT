/*
 * Copyright (C) 2016 Cenk Gündoğan <mail@cgundogan.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */
#include <errno.h>
#include <stdint.h>

#include "embUnit/embUnit.h"

#include "color.h"

#include "tests-color.h"

static void test_str2rgb__success(void)
{
    const char *color_str = "F09A1D";
    color_argb_t color;

    color_str2rgb(color_str, &color);
    TEST_ASSERT_EQUAL_INT(0xF0, color.argb.r);
    TEST_ASSERT_EQUAL_INT(0x9A, color.argb.g);
    TEST_ASSERT_EQUAL_INT(0x1D, color.argb.b);
}

static void test_rgb2str__success(void)
{
    char color_str[7] = { 0 };
    color_argb_t color;

    color.argb.r = 0x0A;
    color.argb.g = 0xB1;
    color.argb.b = 0x3C;

    color_rgb2str(&color, color_str);

    TEST_ASSERT_EQUAL_STRING("0AB13C", (char *) color_str);
}

Test *tests_color_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_str2rgb__success),
        new_TestFixture(test_rgb2str__success),
    };

    EMB_UNIT_TESTCALLER(color_tests, NULL, NULL, fixtures);

    return (Test *)&color_tests;
}

void tests_color(void)
{
    TESTS_RUN(tests_color_tests());
}
/** @} */
