#!/usr/bin/python3

"""`ecc` - Elliptic Curve Cryptography module

Contains classes and methods necessary for implementing an educational mockup
of the secp256k1 ECC used in the Bitcoin mainnet.

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
            raise ValueError(
                'Num {} not in field range 0 to {}'.format(
                num, prime - 1))
        self.num = num
        self.prime = prime

    def __repr__(self):
        """Generates string representation of FiniteFieldElem.

        Returns:
            (str): representation of self

        """
        return '{}_{}({})'.format(self.__class__, self.prime, self.num)

    def __eq__(self, other):
        """Evaulates equality of finite field elements.

        Args:
            other (self.__class__): element to compare

        Returns:
            bool: True if equal, False otherwise

        """
        if type(other) is not self.__class__:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        """Evaulates inequality of finite field elements.

        Args:
            other (self.__class__): element to compare

        Returns:
            bool: True if inequal, False otherwise

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


class ECPoint:
    """Class representing a point on an elliptic curve.

    A representation of a point on an elliptic curve, or a set of coordinates
    (x, y) defined by:

        y**2 == x**3 + a * x + b

    for any two constants a and b. Such a set of points should have many of the
    properties of addition:

       Identity:
           A point exists such that adding it to another point does not change
           the point's values. Here the identity is called the infinity point,
           represented by x and y values of `None`.
       Invertability:
           For every point on the curve, there is a point to which adding it
           results in the identity.
       Commutativity:
           P1 + P2 == P2 + P1
       Associativity:
           (P1 + P2) + P3 == P1 + (P2 + P3)

    Attributes:
        a (int/float): first constant
        b (int/float): second constant
        x (int/float): x coordinate
        y (int/float): y coordinate

    """

    def __init__(self, x, y, a, b):
        """Instantiate an ECPoint object.

        Args:
            a (int/float): first constant
            b (int/float): second constant
            x (int/float): x coordinate
            y (int/float): y coordinate

        """
        # No need to evaluate infinity point
        if x is not None and y is not None and y**2 != x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))
        self.a = a
        self.b = b
        self.x = x
        self.y = y

    def __repr__(self):
        """Generates string representation of elliptic curve point.

        Returns:
            (str): representation of self

        """
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other):
        """Evaulates equality of elliptic curve points.

        Args:
            other (self.__class__): point to compare

        Returns:
            bool: True if equal, False otherwise

        """
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        """Evaulates inequality of elliptic curve points.

        Args:
            other (self.__class__): point to compare

        Returns:
            bool: True if inequal, False otherwise

        """
        return not self == other


    def __add__(self, other):
        """Adds one elliptic curve point to another.

        Sums of elliptic curve points can be considered as lines intersecting
        the curve, and come in several varieties:

            Intersecting at three points:
                The sum of the points is the third intersection of the curve by
                a line desrcibed by P1 and P2.
            Intersecting at two points (vertical line):
                P2 is the inverse of P1; sum is the identity, or infinity point.
            Intersecting at two points (line tangent to curve):
                P1 == P2, sum is a different point on the curve.
            Intersecting at one point:
                P1 + identity, sum is P1.

        Args:
            other (self.__class__): point to add

        Returns:
            (self.__class__): sum of points

        """

        if self.a != other.a or self.b != other.b:
            raise TypeError(
                'Points {}, {} are not on the same curve'.format(self, other))

        # Intersection at one point (any point added to identity is itself)
        if self.x is None:
            return other
        if other.x is None:
            return self

        if self == other:
            # Line is tangent to the curve, intersecting at two points
            s = (3 * self.x**2 + self.a) / (2 * self.y)  # slope
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        elif self.x == other.x:
            # Vertical line, intersection at two points, sum is infinity point
            return self.__class__(None, None, self.a, self.b)
        else:
            # Intersection at three points
            s = (other.y - self.y) / (other.x - self.x)  # slope
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
