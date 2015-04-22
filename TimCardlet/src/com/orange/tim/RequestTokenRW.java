/*
* 
* Copyright (C) 2015 Orange Labs
* 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
*    http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* 
*/

package com.orange.tim;

import javacard.framework.Util;
import javacard.security.Key;

public  class RequestTokenRW {

	static final short ZERO = (short) 0;
	static final short ONE  = (short) 1;
	static final short TWO  = (short) 2;
	static final short THREE= (short) 3;
	static final short FOUR = (short) 4;
	static final short FIVE = (short) 5;
	
	byte [] tr_buffer;
	
	public RequestTokenRW(short size) {
		tr_buffer = new byte [size];
		reset();
	}
	
	public void reset() {
		Util.setShort(tr_buffer, ZERO, ZERO);
		Util.setShort(tr_buffer, ONE, THREE);
	}
	
	static short skipParam(byte [] buffer, short paramCount, short offset) {
		short size = ZERO;
		for(byte i=0; i<paramCount; i++) {
			size   = Util.getShort( buffer, offset);
			offset += ( size + 2 );
		}
		return offset;
	}
	
	short getTokens( short offset, byte [] dest_buffer, short dest_offset ) {
		// skip request param
		short size = (short)( skipParam(tr_buffer, THREE, offset) - offset );
		// copy only tokens
		Util.arrayCopy(tr_buffer, offset, dest_buffer, dest_offset, size);
		return size;
	}
	
	short getTokensAndAppKeys( short offset, byte [] dest_buffer, short dest_offset ) {
		// skip request param
		short size = (short)( skipParam(tr_buffer, FIVE, offset) - offset );
		// copy tokens and public key
		Util.arrayCopy(tr_buffer, offset, dest_buffer, dest_offset, size);
		return size;
	}
	
	short getTokensAndPubKey( short offset, byte [] dest_buffer, short dest_offset ) {
		// skip request param
		short size = (short)( skipParam(tr_buffer, FOUR, offset) - offset );
		// copy tokens and public key
		Util.arrayCopy(tr_buffer, offset, dest_buffer, dest_offset, size);
		return size;
	}
	
	boolean setRequestToken( byte [] req_buffer, byte [] tokenkey_buffer ) {

		// compute true data size
		short request_size = skipParam(req_buffer,FOUR,ZERO);
		short tokenkey_size  = skipParam(tokenkey_buffer,FIVE,ZERO);

		// total block size
		short data_size = (short) (request_size + tokenkey_size);

		short offset = searchRequest( req_buffer, request_size );
		
		// not found, so add new
		if(offset==-1) {
			// get next free block offset
			offset = Util.getShort(tr_buffer, ONE);

			// check space left
			if( ((short)(tr_buffer.length - offset)) < data_size ) {
				// not enough space left
				return false;
			}

			// increment block count
			tr_buffer[ZERO]++;
			
			// write size of block
			offset = Util.setShort(tr_buffer, offset, data_size);
			// write blocks
			offset = Util.arrayCopy(req_buffer,      ZERO, tr_buffer, offset, request_size);
			offset = Util.arrayCopy(tokenkey_buffer, ZERO, tr_buffer, offset, tokenkey_size);
			// update next free block
			Util.setShort(tr_buffer, ONE, offset);
			
			return true;
		}

		// block found, check size
		short block_size = Util.getShort(tr_buffer, offset);
		if( block_size < data_size ) {
			// need compact
			offset = compactBlocks( offset );
			
			short space_left = (short)(tr_buffer.length - offset);
			
			// check space left
			if( space_left < data_size ) {
				// not enough space left, just update next free block after compact
				Util.setShort(tr_buffer, ONE, offset);
				return false;
			}

			// write new size of block
			offset = Util.setShort(tr_buffer, offset, data_size);

			// update next free block
			Util.setShort(tr_buffer, ONE, (short) (offset+data_size));

			// re-write request data
			offset = Util.arrayCopy(req_buffer, ZERO, tr_buffer, offset, request_size);

		} else {
			// skip block_size and req buffer
			offset += TWO + request_size;
		}
		
		// write tokens key data
		Util.arrayCopy(tokenkey_buffer, ZERO, tr_buffer, offset, tokenkey_size);

		return true;
	}

	// remove data if found
	public boolean removeRequestData(byte[] requestData) {
		short offset = searchRequest( requestData );
		
		// check if found
		if(offset==-1)
			return false;
		
		// compact block
		offset = compactBlocks( offset );

		// update next free block after compact
		Util.setShort(tr_buffer, ONE, offset);

		// decrement block count
		tr_buffer[ZERO]--;
		
		return true;
	}

	
	// return offset of request data, -1 if not found
	short searchRequestData( byte [] request_buffer ) {
		short request_size = skipParam(request_buffer, FOUR, ZERO);
		short offset =  searchRequest( request_buffer, request_size );
		if( offset != -1 ) {
			offset += request_size+2;
		}
		return offset;
	}
	
	short searchRequest( byte [] request_buffer ) {
		return searchRequest( request_buffer, skipParam(request_buffer, FOUR, ZERO) );
	}
	
	short searchRequest( byte [] data, short search_size ) {

		// check at least one block
		if( tr_buffer[0] > 0 ) {

			short next_free_block = Util.getShort( tr_buffer, ONE );
			short offset = THREE;
			
			// while end not reach
			while(offset < next_free_block) {
				short block_size = Util.getShort( tr_buffer, offset );
				short block_offset = (short) (offset+TWO);
				
				if ( Util.arrayCompare(tr_buffer, block_offset, data, ZERO, search_size) == 0) {
					// found it, return offset
					return offset;
				}

				// try next
				offset = (short) (block_offset+block_size);
			}
		}
		
		return -1;
	}
	
	short compactBlocks( short offset ) {

		short next_free_offset  = Util.getShort( tr_buffer, ONE );
		short block_size        = (short) ( Util.getShort( tr_buffer, offset ) + TWO );
		short next_block_offset = (short) ( offset + block_size );
		
		short size = (short)(next_free_offset-next_block_offset);
		if(size>0) {
			return Util.arrayCopy(tr_buffer, next_block_offset, tr_buffer, offset, size);
		}
		return offset;
	}

	short getFreeSpace() {
		if(tr_buffer==null) return ZERO;
		
		short next_free_offset  = Util.getShort( tr_buffer, ONE );
		
		return ((short)(tr_buffer.length-next_free_offset));
	}

	void sign( Key key, byte [] in_buffer, byte [] out_buffer) {
	}
}
