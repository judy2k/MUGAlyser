'''
Created on 5 Dec 2016

@author: jdrumgoole
'''
import unittest

from mugalyser.mongodb import MUGAlyserMongoDB
from mugalyser.groups import Groups

class Test_groups(unittest.TestCase):


    def setUp(self):
        self._mdb = MUGAlyserMongoDB( uri="mongodb://localhost/TEST_DATA_MUGS" )
        self._groups = Groups( self._mdb)


    def tearDown(self):
        self._mdb.client().drop_database( "TEST_MUGS" )


    def testGroups(self):
        groups = self._groups.get_all_groups()
        print( len( list( groups )))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()