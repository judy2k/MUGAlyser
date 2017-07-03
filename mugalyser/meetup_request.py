'''

Refactored. Make requests and return generators with a list of result
objects. Designed to handle paging interface for Meetup.com's API.

Created on 29 Jun 2017

@author: jdrumgoole
'''
import logging
import requests
import time
import pprint

from mugalyser.version import __programName__
from mugalyser.logger import Logger

class MeetupRequest( object ):
    
    def __init__(self ):
        
        self._logger = Logger( __programName__).log()
        
    def simple_request(self, req, params=None ):
        
        if params :
            r = requests.get( req, params )
        else:
            r = requests.get( req )
            
        self._logger.debug( "simple_request( %s )",  r.url )

        try:
            r.raise_for_status()
#           for req_data in r.iter_lines():
#                     if req_data:
#                         print( "req_data")
#                         #pprint.pprint( req_data )
#                         json_data = json.loads(req_data)
            
            '''
            Rate limiting
            '''
            remaining = int( r.headers[ "X-RateLimit-Remaining"] )
            resetDelay = int( r.headers[ "X-RateLimit-Reset"] )
            if remaining <= 1 and resetDelay > 0 :
                self._logger.debug( "Sleeping for : %i", resetDelay )
                time.sleep( resetDelay )
                
            return ( r.headers, r.json())
        
        except ValueError :
            self._logger.error( "ValueError in makeRequests:")
            self._logger.error( "request: '%s'", r.url)
            self._logger.error( "headers:" )
            self._logger.error( pprint.pformat( r.headers ))
            self._logger.error( "text:" )
            self._logger.error( r.text )
            raise
        
        except requests.HTTPError, e :
            self._logger.error( "HTTP Error  : %s:", e )
            raise

    def getHref( self, s ):
        ( link, direction ) = s.split( ";", 2 )
        link = link[ 1:-1]
        ( _, direction ) = direction.split( "=", 2 )
        direction = direction[ 1:-1 ]
        return ( link, direction )
    
    def getNextPrev(self, header ):
        
        #headerDict = json.loads( header )
        link = header[ "Link" ]
        
        if "," in link : # has prev  and next fields
            ( nxt, prev ) = link.split( ",", 2 )
            ( nextLink, _ ) = self.getHref( nxt )
            ( prevLink, _ )  = self.getHref( prev )
        else:
            ( link, direction ) = self.getHref( link )
            #print( "direction: '%s'" % direction )
            if direction == "next" :
                nextLink = link
                prevLink = None
            else:
                prevLink = link
                nextLink = None
        
        return ( nextLink, prevLink )
    
    def paged_request(self, req, params ):
        '''
        Takes a request and hands it off to the paginator API. It does this by initiating the request
        to get the first document back and then using it to look for headers.
        '''
        
        #print( "request: %s, %s" % ( req, params ))

        #print( "Intiate paginated request") 
 
        (header, body) = self.simple_request( req, params )
    
#         print( "header" )
#         pprint.pprint( header )
#         print( "body")
#         pprint.pprint( body )
        #print( "Paginator")
        #r = requests.get( self._api + url_name + "/events", params = params )
        #print( "request: '%s'" % r.url )
        #print( "header: '%s' )
        return self.next_page( header, body, params  )
    
    def next_page( self, headers, body, params ):
        '''
        Meetup API returns results as pages. The old API embeds the 
        page data in a meta data object in the response object. The new API
        returns page data in the Header info. 
        
        Func is a function that takes a doc and returns a doc. Right now
        we use this to reshape geospatial coordinates into a format that MongoDB
        understands and to convert  meetup timestamps to datetime objects.
        
        next_page is a generator which yields results.
        
        '''
        #print( "paginator( header= '%s'\n, body='%s'\n, params='%s'\n)" % ( headers, body, params ))
        #print( "paginatorEntry( %s )" % headers )
            

        #pprint.pprint( data )
        
        # old style format 
        if "meta" in body :
            for i in body[ "results"]:
                yield i
        
            count = 0
            nested_body = body
            while ( nested_body[ 'meta' ][ "next" ] != ""  ) :

                ( _, nested_body ) = self.simple_request( nested_body['meta'][ 'next' ] )
                count = count + 1
                #print( "Nested Body")
                #print( nested_body )
                if nested_body:
                    for i in nested_body[ "results"]:
                        yield  i 
    
                    
        elif ( "Link" in headers ) : #new style pagination
            for i in body :
                yield i
               
            count = 0 
            ( nxt, _) = self.getNextPrev(headers)

            
            while ( nxt is not None ) : # no next link in last page

                count = count + 1 
                #print( "make request (new): %i" % count )
                    
                #print( "V2 Paged SimpleRequest( %s, %s)" % ( nxt, params))
                ( headers, body ) = self.simple_request( nxt, params )
                ( nxt, _ ) = self.getNextPrev(headers)
                for i in body :
                    yield i
    
        else: # new style but we have all the data
            for i in body:
                yield  i