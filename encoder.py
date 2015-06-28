
import base64
from   Crypto.Cipher import AES
from   random        import Random
import os

PADDING       = '|'
MODE          = AES.MODE_CBC
FILENAMECACHE = set()
CHARACTERS    = 'abcdefghijklmnopqrstuvwxyz' + \
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + \
                '0123456789_'

def encryptfile( filepath, key, initializationvector ):
    with open( filepath, 'r' ) as f:
        data = f.read()
	efilepath = encrypt( filepath, key, initializationvector )
    return '%s\n%s' % ( efilepath, encrypt( data, key, initializationvector ) )

def encrypt( data, key, initializationvector ):
	BLOCK_SIZE = 16
	pad        = lambda s: s + ( BLOCK_SIZE - len( s ) % BLOCK_SIZE ) * PADDING
	EncodeAES  = lambda c, s: base64.b64encode( c.encrypt( pad( s ) ) )
	cipher     = AES.new( key=key * 2, mode=MODE, IV=initializationvector )
	encoded    = EncodeAES( cipher, data )
	return encoded

def _randomname():
    rand   = Random()
    choose = rand.choice
    part1  = ''.join( choose( CHARACTERS ) for _dummy in xrange( 20 ) )
    part2  = os.getpid()
    return '%s_%s' % ( part1, part2 )

def generatefilename():
    global FILENAMECACHE
    name = _randomname()
    while name in FILENAMECACHE:
        name = _randomname()
    FILENAMECACHE.add( name )
    return name

def savefile( data, filepath=r'c:\tmp' ):
    with open( r'%s\%s' %( filepath, generatefilename() ), 'w' ) as f:
        f.write( data )

def decryptfile( filepath, key, initializationvector ):
    with open( filepath, 'r' ) as f:
        data = f.read()
    efilepath, edata = data.split( '\n' )[ 0 ], '\n'.join( data.split( '\n' )[ 1 : ] )
    dfilepath = decrypt( efilepath, key, initializationvector )
    ddata     = decrypt( edata, key, initializationvector )
    return ( dfilepath, ddata )

def decrypt( data, key, initializationvector ):
	DecodeAES  = lambda c, e: c.decrypt( base64.b64decode( e ) ).rstrip( PADDING )
	cipher     = AES.new( key=key * 2, mode=MODE, IV=initializationvector )
	decoded    = DecodeAES( cipher, data )
	return decoded
