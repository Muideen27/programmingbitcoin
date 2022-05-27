#!/usr/bin/python3

"""`ecc` - Elliptic Curve Cryptography module

Contains classes and methods necessary for implementing an educational mockup
of the SHA256pk1 ECC used in the Bitcoin mainnet.

Modified from original code base developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

class FiniteFieldElem:
    """Class representing a finite field element.

    A representation of a finite field element, or a value in a set of
    integers from 0 to a prime - 1, for which arithmetic operations are
    defined with a modulo so that any resulting values are also in the set.

    Attributes:
        num   (int): value in the finite field set
        prime (int): prime number that is the upper bound of the set, also
            known as its "order"

    """
    def __init__(self, num, prime):
        """Instantiate a FiniteFieldElem object.

        Args:
            num   (int): finite field member
            prime (int): finite field order

        Note:
            Currently there is no validation of prime as a prime number,
            ideally a ValueError would be thrown if not.

        """
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(
                num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        """Generates string representation of FiniteFieldElem.

        Returns:
            (str): readable representation of self

        """
        return '{}_{}({})'.format(self.__class__, self.prime, self.num)

    def __eq__(self, other):
        """Evaulates equality of finite field elements.

        Args:
            other (FiniteFieldElem): element to compare

        Returns:
            bool: True if equal, False otherwise

        """
        if type(other) is not self.__class__:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        """Evaulates inequality of finite field elements.

        Args:
            other (FiniteFieldElem): element to compare

        Returns:
            bool: True if not equal, False otherwise

        """
        if type(other) is not self.__class__:
            return True
        return self.num != other.num or self.prime != other.prime

    def __add__(self, other):
        """Adds one finite field element to another.

        Args:
            other (self.__class__): element to add

        Returns:
            (self.__class__): sum of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError('Can only add other elements in the same field')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        """Subtracts one finite field element from another.

        Args:
            other (self.__class__): element to subtract

        Returns:
            (self.__class__): difference of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError('Can only subtract other elements in the same field')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        """Multiplies one finite field element by another.

        Args:
            other (self.__class__): multiplier element

        Returns:
            (self.__class__): product of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError('Can only multiply by other elements in the same field')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        """Exponentiates a finite field element.

        Args:
            other (int): exponent (only base needs to be inside the field)

        Returns:
            (self.__class__): product of elements

        """
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        """Divides one finite field element by another.

        To arrive at a means of finite field division, we can combine Fermat's
        Little Theorem, or:

            n**(p - 1) % p == 1 for p > n > 0

        with expressing division as multiplication by the inverse:

            a / b == a * (1 / b) == a * b**-1

        such that:

            b**-1 == b**-1 * (b**(p - 1) % p) == b**(p - 2) % p

        and so:

            a /f b = (a * (b**(p - 2) % p)) % p

        Args:
            other (self.__class__): divisor element

        Returns:
            (self.__class__): quotient of elements

        """
        if type(other) is not self.__class__ or self.prime != other.prime:
            raise TypeError('Can only divide by other elements in the same field')
        num = (self.num * pow(other.num, other.prime - 2, other.prime)) % self.prime
        return self.__class__(num, self.prime)
