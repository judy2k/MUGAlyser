'''
Created on 20 Apr 2017

@author: jdrumgoole
'''
import unittest
from mugalyser.apikey import get_meetup_key
from mugalyser.meetup_writer import MeetupWriter
from mugalyser.mongodb import MUGAlyserMongoDB
from mugalyser.audit import Audit
class Test(unittest.TestCase):

    def tearDown( self ):
        self._mdb.client().drop_database( "TESTWRITER" )
        
    def test_write_group(self):
        self._mdb = MUGAlyserMongoDB("mongodb://localhost:27017/TESTWRITER")
        self._audit = Audit( self._mdb )
        batchID = self._audit.start_batch({ "test" : 1} )
        self._writer = MeetupWriter( get_meetup_key(), batchID, self._mdb )
        self._writer.write_groups(  "nopro", ["DublinMUG" ] )
        self._writer.write_groups( "pro" , [ "DublinMUG" ] )
        self.assertTrue( self._mdb.groupsCollection().find_one( { "group.urlname" : "DublinMUG"}))
        self.assertTrue( self._mdb.proGroupsCollection().find_one( { "group.urlname" : "DublinMUG"}))
        self._audit.end_batch(batchID)

            
    def testProcessMembers(self):
        self._mdb = MUGAlyserMongoDB("mongodb://localhost:27017/TESTWRITER")
        self._audit = Audit( self._mdb )
        batchID = self._audit.start_batch({ "test" : 2 } )
        self._writer = MeetupWriter( get_meetup_key(), batchID, self._mdb )
        self._writer.write_members( "pro" , [ "DublinMUG" ] )
        self._writer.write_members( "nopro" , [ "DublinMUG" ] )
        self.assertTrue( self._mdb.proMembersCollection().find_one( { "member.member_name" : "Joe Drumgoole"}))
        self.assertTrue( self._mdb.membersCollection().find_one( { "member.name" : "Joe Drumgoole"}))
        self._audit.end_batch(batchID)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()