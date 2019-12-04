import unittest

def return_name(name):
    return name

def junk():
    raise ValueError

class MyTest(unittest.TestCase):
    def test(self):
        self.assertEqual(return_name('zach'), 'zach')

    def test2(self):
        self.assertRaises(KeyError, junk)

if __name__ == "__main__":
    unittest.main()