#!/usr/bin/python3
"""Unit test module for ecc.py

Modified from original code base developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

from unittest import TestCase
from unittest import main
import ecc
FiniteFieldElem = ecc.FiniteFieldElem


class TestFiniteFieldElem(TestCase):
    """Unit tests for FiniteFieldElem object methods.

    """
    def test_init(self):
        # instantiate valid field element
        a = FiniteFieldElem(2, 31)
        self.assertTrue(a.num == 2 and a.prime == 31)
        # Error for negative num values
        self.assertRaises(ValueError, FiniteFieldElem, -1, 31)
        # Error for num values >= order(prime)
        self.assertRaises(ValueError, FiniteFieldElem, 31, 31)

    def test_repr(self):
        a = FiniteFieldElem(2, 31)
        self.assertEqual(a.__repr__(), '{}_{}({})'.format(
            a.__class__, a.prime, a.num))

    def test_eq(self):
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(2, 31)
        c = FiniteFieldElem(2, 10)
        # Addition with member of same field
        self.assertEqual(a, b)
        # Comparing to non-field element types always inequal
        self.assertFalse(a == 2)
        # Comparing to members of other fields always inequal
        self.assertFalse(a == c)

    def test_ne(self):
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(2, 31)
        c = FiniteFieldElem(15, 31)
        d = FiniteFieldElem(2, 10)
        self.assertEqual(a, b)
        # Inequal elements of same field
        self.assertTrue(a != c)
        # Equal elements of same field
        self.assertFalse(a != b)
        # Comparing to non-field element types always inequal
        self.assertTrue(a != 2)
        # Comparing to members of other fields always inequal
        self.assertTrue(a != d)

    def test_add(self):
        a = FiniteFieldElem(2, 31)
        b = FiniteFieldElem(15, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__add__, a,
        FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__add__, a, 2)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FiniteFieldElem(17, 31))
        a = FiniteFieldElem(17, 31)
        b = FiniteFieldElem(21, 31)
        # a +f b == (a + b) % p
        self.assertEqual(a + b, FiniteFieldElem(7, 31))

    def test_sub(self):
        a = FiniteFieldElem(29, 31)
        b = FiniteFieldElem(4, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__sub__, a,
        FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__sub__, a, 2)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FiniteFieldElem(25, 31))
        a = FiniteFieldElem(15, 31)
        b = FiniteFieldElem(30, 31)
        # a -f b == (a - b) % p
        self.assertEqual(a - b, FiniteFieldElem(16, 31))

    def test_mul(self):
        a = FiniteFieldElem(24, 31)
        b = FiniteFieldElem(19, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__mul__, a,
        FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__mul__, a, 2)
        # a *f b == (a * b) % p
        self.assertEqual(a * b, FiniteFieldElem(22, 31))

    def test_pow(self):
        a = FiniteFieldElem(17, 31)
        # a **f b == (a ** b) % p
        self.assertEqual(a**3, FiniteFieldElem(15, 31))
        a = FiniteFieldElem(5, 31)
        b = FiniteFieldElem(18, 31)
        # a **f 5 *f b == (a**5 * b) % p
        self.assertEqual(a**5 * b, FiniteFieldElem(16, 31))
        a = FiniteFieldElem(17, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-3, FiniteFieldElem(29, 31))
        a = FiniteFieldElem(4, 31)
        b = FiniteFieldElem(11, 31)
        # a **f n == a **f (n % (p - 1))
        self.assertEqual(a**-4 * b, FiniteFieldElem(13, 31))

    def test_div(self):
        # Note: __truediv__ implemented, not __floordiv__
        a = FiniteFieldElem(3, 31)
        b = FiniteFieldElem(24, 31)
        # Error when comparing to members of other fields
        self.assertRaises(TypeError, FiniteFieldElem.__truediv__, a,
        FiniteFieldElem(2, 10))
        # Error when comparing to non-field element types
        self.assertRaises(TypeError, FiniteFieldElem.__truediv__, a, 2)
        # a /f b == a /f (b **f (p - 2))
        self.assertEqual(a / b, FiniteFieldElem(4, 31))


if __name__ == '__main__':
    unittest.main()
