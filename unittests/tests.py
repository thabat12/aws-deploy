import json
import boto3
import unittest


# Arrange, Act, Assert model of testing
def sum(a, b):
    return a + b

# must inherit from the unittest.TestCase
class LambdaTests(unittest.TestCase):
    # note that tests should start with the "test" keyword
    
    # note that setup is called before every test function!
    def setUp(self):
        # arrange

        self.a = 10
        self.b = 20

    # this is ran after every test function!
    def tearDown(self):
        print('tearDown called')

    def test_sum_func1(self):
        print('test1')
        # act
        res = sum(self.a, self.b)

        # assert
        self.assertEqual(res, self.a + self.b)

    def test_sum_func2(self):
        print('test2')
        # act
        res = sum(self.b, self.a)

        # assert
        self.assertEqual(res, self.a + self.b)

if __name__ == "__main__":
    unittest.main()