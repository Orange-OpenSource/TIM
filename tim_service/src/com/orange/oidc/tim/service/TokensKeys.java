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

package com.orange.oidc.tim.service;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * 
 * class TokensKeys
 * used to read and make buffer to and from SIM card
 */
public class TokensKeys {
	String id_token;
	String access_token;
	String refresh_token;
	String expires;
	String serverScope;
	long   timems;
	
	String jwkPub;
	
	RSAPublicKey  pubKey;
	RSAPrivateKey privKey;

	public TokensKeys() {
		timems = 0;
	}
	
	// parse a byte buffer and read each field of a TokensKeys object
	static TokensKeys makeFromBuffer(byte[] buffer) {
		try {
			TokensKeys tokens_keys = new TokensKeys();
			int offset = 0;
			
			// read id_token
			int size = readInt(buffer, offset);
			if(size>0 && (offset+size) < buffer.length) {
				tokens_keys.id_token = new String(buffer, offset+2, size);
			}

			// read refresh_token
			offset += 2 + size;
			size = readInt(buffer, offset);
			if(size>0 && (offset+size) < buffer.length) {
				tokens_keys.refresh_token = new String(buffer, offset+2, size);
			}
			
			// read expiration date
			offset += 2 + size;
			size = readInt(buffer, offset);
			if(size>0 && (offset+size) < buffer.length) {
				tokens_keys.expires = new String(buffer, offset+2, size);
				// tokens_keys.timems = ByteBuffer.wrap(KryptoUtils.decodeB64(tokens_keys.expires)).getLong();
				try {
					tokens_keys.timems = Long.parseLong(tokens_keys.expires)*1000;
				} catch (Exception e) {}
			}

			// read public key
			offset += 2 + size;
			size = readInt(buffer, offset);
			if(size>0 && (offset+size) < buffer.length) {
				byte pub_key [] = new byte[size];
				System.arraycopy(buffer, offset+2, pub_key, 0, size);
				String pubKey64 = KryptoUtils.encodeB64(pub_key);

				JSONObject jk = new JSONObject();
				jk.put("kty", "RSA");
				jk.put("kid", "k2bdc");
				jk.put("e", "AQAB");
				
				jk.put("n", pubKey64);
	        	JSONArray ja = new JSONArray();
	        	ja.put(jk);
	        	JSONObject jo = new JSONObject();
	        	jo.put("keys", ja);
	        	
	        	tokens_keys.jwkPub = jo.toString();
			}

			return tokens_keys;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	// read 2 bytes integer at specified offset 
	static int readInt(byte[] buffer, int offset) {
		return (( buffer[offset] & 0x00FF ) << 8) + ( buffer[offset+1] & 0x00FF );
	}
	
	// prepare a byte buffer where tokens and key are stored in the SIM card
	byte [] makeBuffer4SIM() {
		try {
			// prepare key buffer
	    	byte [] privExp = privKey != null ? privKey.getPrivateExponent().toByteArray() : null;
	    	byte [] modulus = pubKey  != null ? pubKey.getModulus().toByteArray() : null;
	    	
	    	// calculate buffer size
	    	int buffsize = 0;
	    	buffsize += 2 + ( id_token      != null ? id_token.length()      : 0 );
	    	buffsize += 2 + ( refresh_token != null ? refresh_token.length() : 0 );
	    	buffsize += 2 + ( expires       != null ? expires.length()       : 0 );
	    	buffsize += 2 + ( modulus       != null ? modulus.length         : 0 );
	    	buffsize += 2 + ( privExp       != null ? privExp.length         : 0 );

	    	// allocate buffer according to size
	       	byte [] buffer = new byte[buffsize+2];

	       	// copy data
	       	buffer[0] = (byte)((buffsize&0x00FF00)>>8);
	       	buffer[1] = (byte)(buffsize&0x00FF);

	       	// copy each token and key
	       	int offset = 2;
	       	offset = copyToBuffer( buffer, offset, ( id_token!=null      ? id_token.getBytes("UTF8") : null ) );
	       	offset = copyToBuffer( buffer, offset, ( refresh_token!=null ? refresh_token.getBytes("UTF8") : null ) );
	       	offset = copyToBuffer( buffer, offset, ( expires!=null       ? expires.getBytes("UTF8") : null ) );
	       	offset = copyToBuffer( buffer, offset, modulus);
	       	offset = copyToBuffer( buffer, offset, privExp);

	       	// return prepared buffer
	       	return buffer;

		} catch (Exception e) {
			e.printStackTrace();
		}
    	
		// error occurred, nothing to return
		return null;
	}

	// copy a data parameter in the buffer at specified offset
	static int copyToBuffer(byte buffer[], int offset, byte data[]) {
		// check destination buffer
		if( buffer == null ) return 0;
		
		// get data length
    	short length = 0;
    	if(data!=null)
    		length = (short)data.length;
    	
    	// copy length to buffer
    	buffer[offset++] = (byte) (( (length & 0x00FF00)>>> 8 ) & 0xFF);
    	buffer[offset++] = (byte) ( length & 0xFF);

    	// copy data to buffer
       	if( length > 0 )
       		System.arraycopy(data, 0, buffer, offset, length);
       	
       	// return offset position
    	return offset+length;
    }
	
	// check if JWT string has not expired
	static boolean isTokenValid(String token) {
		if(token!=null) {
			Token t = new Token(token);
			return (t.isExpired()==false);
		}
		return false;
	}
	
	// return validity of id token
	boolean isIdTokenValid() {
		return isTokenValid(id_token);
	}
	
	// return validity of access token
	boolean isAccessTokenValid() {
		return isTokenValid(access_token);
	}
	// return validity of refresh token
	boolean isRefreshTokenValid() {
		// return isTokenValid(refresh_token);
        //[NBAN] TODO verification de l'expiration à partir de la chaine de caractère et non le timems qui n'est pas set dans le cas du SDStorage
        if ((timems == 0) && (this.expires != null)){
            Calendar cal = fromStringToDate(this.expires);
            return cal.after(Calendar.getInstance());
        } else if (timems != 0) {
			Calendar calNow = Calendar.getInstance();
			calNow.setTimeZone(TimeZone.getTimeZone("GMT"));
			long now = calNow.getTimeInMillis();
			return timems > now;
        }
        return false;
	}
	
	// convert current object to a JSON string
	String toJsonString() {
		if( id_token == null && access_token == null && refresh_token == null )
			return null;

		JSONObject json = new JSONObject();
		try {
			if(id_token!=null)
				json.put(new String("id_token"), id_token);
			
			if(access_token!=null)
				json.put(new String("access_token"), access_token);
			
			if(refresh_token!=null)
				json.put(new String("refresh_token"), refresh_token);

			if(jwkPub!=null)
				json.put(new String("public_key"), jwkPub);

			if(expires!=null) {
				json.put(new String("expires"), getExpires());
			}
		} catch(Exception e) {
			
		}
		
		return json.toString();
	}
	
	// return a human readable date from timems attribute
	String getExpires() {
		if(expires!=null && timems !=0) {
			Calendar cal = Calendar.getInstance();
			cal.setTimeInMillis(timems);
			return  "" +cal.get(Calendar.DAY_OF_MONTH)
				+ "/"+cal.get(Calendar.MONTH)
				+ "/"+cal.get(Calendar.YEAR)
				+ " "+cal.get(Calendar.HOUR)
				+ ":"+cal.get(Calendar.MINUTE)
				+ ":"+cal.get(Calendar.SECOND);
		} else if (expires!=null) {
            Calendar cal = Calendar.getInstance();
            cal = fromStringToDate(expires);
            if (cal !=null) {
                return "" + cal.get(Calendar.DAY_OF_MONTH)
                        + "/" + cal.get(Calendar.MONTH)
                        + "/" + cal.get(Calendar.YEAR)
                        + " " + cal.get(Calendar.HOUR)
                        + ":" + cal.get(Calendar.MINUTE)
                        + ":" + cal.get(Calendar.SECOND);
			}
        }
		
		return "";
		
	}

	// return a base64 encoded expiration time value
	static String makeExpires64(String durationExpires) {
		if(durationExpires!=null) {
			try {
				int duration = Integer.parseInt(durationExpires);
				if(duration>1) {
					Calendar cal = Calendar.getInstance();
					cal.add(Calendar.SECOND, duration);
					byte[] bytes = ByteBuffer.allocate(8).putLong(cal.getTimeInMillis()).array();
					
					return KryptoUtils.encodeB64(bytes);
					
				}
			} catch (Exception e)  {
				e.printStackTrace();
			}
		}
		
		return "";
	}
    Calendar fromStringToDate(String s) {
        if(s!=null && s.length()>0) {
            try {
                long d = Long.parseLong(s);
                Calendar c = Calendar.getInstance();
    			c.setTimeZone(TimeZone.getTimeZone("GMT"));
                c.setTimeInMillis(d*1000);
                return c;

            } catch ( Exception e ) {
            }
        }
        return null;
    }
}
