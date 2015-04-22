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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Locale;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONObject;
import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.Reader;
import org.simalliance.openmobileapi.SEService;
import org.simalliance.openmobileapi.Session;

import android.util.Base64;
import android.util.Log;

/**
 * 
 * SIMStorage class
 * used to generate crypted and/or signed request objects
 * and to store tokens and generate tim access tokens
 *
 */
public class SIMStorage extends TimSecureStorage {
	protected static final String TAG = "SIM Storage";

	// SecureElementService to communicate with SIM
	public static SEService seService;

	static final String signHeader = "{\"alg\":\"RS256\",\"kid\":\"k2bdc\"}";

	static final int TIM_ACCESS_TOKEN_TIMEOUT = 30;
	
    // SIM FUNCTION VALUES
    
	// APDU indexes
    final static byte IDX_CLA = 0;
    final static byte IDX_INS = 1;
    final static byte IDX_P1  = 2;
    final static byte IDX_P2  = 3;
    final static byte IDX_LC  = 4;
    final static byte IDX_DATA= 5;
    
    final static byte HEADER_SIZE_NO_DATA   = 5;
    final static byte HEADER_SIZE_WITH_DATA = 6;
    
	final byte TIM_SIM_VERSION = 0x02;
	
	// code of CLA byte in the command APDU header
    final static byte TIM_CLA         = (byte) 0x80;
    
    // codes of INS byte in the command APDU header
    final static byte STORE_DATA      = (byte) 0x20;
    final static byte GET_DATA        = (byte) 0x30;
    final static byte CHECK_AR        = (byte) 0x40;
    final static byte AUTH_USER       = (byte) 0x50;
    final static byte MAKE_DATA       = (byte) 0x51;
    
    // code of P1 and P2 parameters for the instruction
    
    // INS: STORE_DATA, possible values for P1
    // final static byte SET_TIME           = (byte) 0x01;
    final static byte SET_TOKENS         = (byte) 0x02;
    final static byte SET_USERINFO       = (byte) 0x03;
    final static byte SET_APP_REQ        = (byte) 0x04;
    // final static byte SET_ID_TOKEN       = (byte) 0x05;
    // final static byte SET_REFRESH_TOKEN  = (byte) 0x06;
    // final static byte SET_REQUEST_OBJECT = (byte) 0x07;
    // final static byte SET_TIM_TOKEN      = (byte) 0x08;
    final static byte UPDATE_TOKENS      = (byte) 0x09;
    final static byte SET_RESET          = (byte) 0x10;
    final static byte DELETE_TOKENS_KEY  = (byte) 0x11;
    final static byte SET_ENCRYPT_DATA   = (byte) 0x12;
    
    // INS: GET_DATA, possible values for P1
    final static byte GET_TIM_ID        = (byte)0x01;
    final static byte GET_TIM_RO        = (byte)0x02;
    final static byte GET_REFRESH_TOKEN_WITH_TIM_APP_KEY = (byte)0x03;
    final static byte GET_ACCESS_TOKEN  = (byte)0x04;
    final static byte GET_USER_INFO     = (byte)0x05;

    final static byte GET_TOKENS_KEY    = (byte)0x07;
    
    final static byte GET_FREE_SPACE    = (byte)0x09;
    final static byte GET_TIM_SECRET    = (byte)0x0A;

    final static byte GET_PUB_KEY       = (byte)0x10;
    final static byte GET_TOKENS        = (byte)0x11;
    final static byte GET_TIM_TKN_SIGN  = (byte)0x12;
    final static byte SEARCH_TOKENS     = (byte)0x13;

    final static byte GET_ALL           = (byte)0x20;
    final static byte GET_TK_ALL        = (byte)0x21;
    final static byte GET_APP_REQ       = (byte)0x22;

    final static byte GET_ENCRYPTED_TIM = (byte)0x23;
    final static byte GET_ENCRYPTED_TAK = (byte)0x24;

    final static byte GET_REDIRECT_URI  = (byte)0x30;

    final static byte GET_VERSION       = (byte)0xF0;


    // INS : MAKE_DATA, possible values for P1
    final static byte GEN_TIM_APP_KEY  = (byte) 0x01;
    
    final static int BLOCK_SIZE = 100;

    // APDU select command to use the TIM cardlet
	final static byte timSelectSIM[] = {
			(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05,
			(byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x00 };

	public SIMStorage() {
		// android.os.Debug.waitForDebugger();
	}
	
	// prepare request buffer to send to SIM
	static byte [] makeRequestBuffer(
    		String server_url,
    		String client_id,
    		String scope
    		) {

    	Logd(TAG, "makeRequestBuffer "+server_url+" / "+client_id+" / "+scope);
    	try {
    		
    		// sort scope in alphabetical order
    		if( scope != null ) {
	    		scope = scope.toLowerCase(Locale.getDefault());
	    		// offline_access is mandatory
	    		if ( !scope.contains("offline_access") ) {
	    			scope += " offline_access";
	    		}
	    		String scopes[] = scope.split("\\ ");
	    		if(scopes!=null) {
	    			Arrays.sort(scopes, new Comparator<String>() {
	    				 @Override
	    				 public int compare(String s1, String s2) {
	    				    return s1.compareToIgnoreCase(s2);
	    				    }
	    				 });
					scope = null;
					// filter null or empty strings
	    			for(int i=0; i<scopes.length; i++) {
	    				if( scopes[i] != null && scopes[i].length()>0 ) {
		    				if(scope==null)
		    					scope = scopes[i];
		    				else
		    					scope += ( " " + scopes[i] );
	    				}
	    			}
	    		}
    		}
    		
    		// compute buffer size
	    	int buffsize = 0;
	    	buffsize += 2 + ( server_url   != null ? server_url.length()   : 0 );
	    	buffsize += 2 + ( client_id    != null ? client_id.length()    : 0 );
	    	buffsize += 2; // redirect_uri not supported any more
	    	buffsize += 2 + ( scope        != null ? scope.length()        : 0 );
	       	
	       	byte [] buffer = new byte[buffsize+2];
	       	
	       	// copy data
	       	int offset = 2;
	       	// update buffer size
	       	buffer[0] = (byte)((buffsize&0x00FF00)>>8);
	       	buffer[1] = (byte)(buffsize&0x00FF);
	       	// update data
	       	offset = copyStringToBuffer( buffer, offset, server_url);
	       	offset = copyStringToBuffer( buffer, offset, client_id);
	       	offset = copyStringToBuffer( buffer, offset, null); // redirect_uri not supported any more
	       	offset = copyStringToBuffer( buffer, offset, scope);
	       	Logd(TAG,"makeRequestBuffer");
	       	Logd(TAG,KryptoUtils.bytesToHex(buffer));
	       	return buffer;
	       	
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
        return null;
    }

	// copy a byte array with size to a buffer
    static int copyParamToBuffer(byte buffer[], int offset, byte []param) {
    	short length = 0;
    	if(param!=null)
    		length = (short)param.length;
       	byte [] sizeArray = new byte[2];
       	sizeArray[0] = (byte) (( length >>> 8 ) & 0xFF);
       	sizeArray[1] = (byte) ( length & 0xFF);
       	System.arraycopy(sizeArray, 0, buffer, offset, 2);
       	offset += 2;
       	if( length > 0 )
       		System.arraycopy(param, 0, buffer, offset, length);
    	return offset+length;
    }

	// convert a string to byte array and copy to a buffer 
    static int copyStringToBuffer(byte buffer[], int offset, String s) {
    	byte data[]=null;
    	if(s!=null) {
    		try {
	    		data = s.getBytes("UTF8");
    		} catch (Exception e) {
    			e.printStackTrace();
	    		data   = null;
    		}
    	}
    	return copyParamToBuffer(buffer, offset, data);
    }

    // read an integer from 2 consecutive byte from a buffer at position defined by offset
	static int readInt(byte[] buffer, int offset) {
		return (( buffer[offset] & 0x00FF ) << 8) + ( buffer[offset+1] & 0x00FF );
	}
    
	public String save_tokens(
			OpenidConnectParams ocp,
			String id_token,
			String refresh_token,
			String expires_in) {
		return save_tokens(ocp, id_token, refresh_token, expires_in, true);
	}

	// save tokens ( id and refresh ) to corresponding request in SIM 
	public String save_tokens(
			OpenidConnectParams ocp,
			String id_token,
			String refresh_token,
			String expires_in,
			boolean sendReq) {

		if(ocp!=null) {
			TokensKeys tokens_keys = new TokensKeys();
			tokens_keys.id_token = id_token;
			tokens_keys.refresh_token = refresh_token;
			int expires = 0;
			try {
				expires = Integer.parseInt(expires_in);
			} catch (Exception e) {}

			Calendar cal = Calendar.getInstance();
			cal.setTimeZone(TimeZone.getTimeZone("GMT"));
			tokens_keys.timems  = cal.getTimeInMillis() + 1000*expires;
			tokens_keys.expires = ""+(tokens_keys.timems/1000); // Long.toHexString(tokens_keys.timems);
			
			return save_app_req_tokens(
					ocp.m_server_url,
					ocp.m_client_id,
					ocp.m_scope,
					tokens_keys,
					sendReq
					);
		}
		return null;
	}

	// send request parameters to SIM
	static int set_app_req(Channel channel, String server_url, String client_id, String scope ) {
		// check channel status
		boolean localChannel = false;
		int response = -1;
		
		// check if channel is opened
		if ( channel == null || channel.isClosed() ) {
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//SIM_setAppReq end : channel error");
				return response;
			}
			localChannel = true;
		}
			// build request data from parameters
			byte req_data [] = makeRequestBuffer(
					server_url,
		    		client_id,
		    		scope
		    		);
			
			if ( req_data != null ) {
				response = sendDataToSIM(channel, SET_APP_REQ, req_data);
				if( response != 0x9000 ) {
					// error
					Logd(TAG, "SIM_setAppReq error send app request : 0x"+toHexa(response));
				}
			}
		try {
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// close channel if locally opened
		if(localChannel && channel!=null && !channel.isClosed()) {
			channel.close();
		}
		
		return response;
	}
	
	// save tokens to specified app request
    static String save_app_req_tokens(
    		String server_url,
			String client_id,
    		String scope,
			TokensKeys tokens_keys,
			boolean sendReq) {
    	
    	String status=null;
    	Channel channel = null;
		try {
			
			// get buffer data
			byte token_key_data [] = tokens_keys.makeBuffer4SIM();
			
			// check if something to do
			if ( token_key_data == null ) return status;
				
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//save_app_req_tokens end : channel error");
				return status;
			}

			int response = 0;
			if( sendReq ) {
				response = set_app_req(channel, server_url, client_id, scope );
				if( response != 0x9000 ) {
					// error
					Logd(TAG, "save_app_req_tokens error send params : 0x"+KryptoUtils.shortToHex(response));
					channel.close();
					return status;
				}
			}
			

			// send token key data
			response = sendDataToSIM(channel, SET_TOKENS, token_key_data);
			status = toHexa(response);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "save_app_req_tokens error send tokens : 0x"+KryptoUtils.shortToHex(response));
				channel.close();
				return status;
			}

		} catch (Exception e) {
			Log.e(TAG, "save_app_req_tokens Error occured:", e);
		}

		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}
		
		return status;
	}

	public String update_tokens(OpenidConnectParams ocp, String id_token,
			String refresh_token, String expires) {
		return update_tokens(ocp, id_token, refresh_token, expires, true);
	}
	
    // update tokens to specified app request
    public String update_tokens(OpenidConnectParams ocp, String id_token, String refresh_token, String expires, boolean sendReq) {
    	TokensKeys tk = new TokensKeys();
    	tk.id_token = id_token;
    	tk.refresh_token = refresh_token;
    	tk.expires = expires;
    	return update_tokens(ocp.m_server_url, ocp.m_client_id, ocp.m_scope, tk, sendReq);
    }

    
    // update tokens to specified app request
    static String update_tokens(
    		String server_url, 
			String client_id, 
    		String scope, 
			TokensKeys tokens_keys, 
			boolean sendReq) {
    	
    	String status=null;
		Channel channel = null;

		try {
			
			byte token_key_data [] = tokens_keys.makeBuffer4SIM();
			if(token_key_data==null) {
				Logd(TAG, "//update_tokens : nothing to update");
				return status;
			}

			// init channel
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//update_tokens end : channel error");
				return status;
			}

			// check existence
			int response = search_tokens(channel, server_url, client_id, scope, true);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "update_tokens error search : "+toHexa(response));
				channel.close();
				status = toHexa(response);
				return status;
			}

			// send update token key data
			response = sendDataToSIM(channel, UPDATE_TOKENS, token_key_data);
			status = toHexa(response);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "update_tokens error : 0x"+KryptoUtils.shortToHex(response));
				channel.close();
				return status;
			}

		} catch (Exception e) {
			Log.e(TAG, "updateTokens Error occured:", e);
		}
		
		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}

		return status;
	}

    // get free SIM storage left on SIM 
    static public String get_free_space() {
    	Channel channel = null;
    	String status=null;

    	try {
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//getFreeSpace end : channel error");
				return status;
			}

			byte []respApdu = channel.transmit(new byte[] { TIM_CLA, GET_DATA, GET_FREE_SPACE, 0x00, 0x00 });
		    status = "" + ( ( (respApdu[0]&0x00FF) << 8 ) + ( respApdu[1]&0x00FF) ); 

    	} catch(Exception e) {
    		e.printStackTrace();
    	}

		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}
    	
    	return status;
    }
    
    // search for stored tokens for given app request
    static public String search_tokens(
    		String server_url, 
    		String client_id, 
    		String scope, 
    		boolean sendReq ) {
    	
    	return toHexa( search_tokens(null, server_url, client_id, scope, sendReq) );
    }
    
    // search for stored tokens for given app request
    static public int search_tokens(
    		Channel channel,
    		String server_url, 
    		String client_id, 
    		String scope, 
    		boolean sendReq ) {
    	
		Logd(TAG, "// searchTokens begin");
		
		boolean localChannel = false;
		int status = 0;

		try {
			if(channel == null) {
				channel = initChannelToSIM();
				if(channel==null) {
					Logd(TAG, "// searchTokens end : channel error");
					return status;
				}
				localChannel = true;
			}

			// send request data (server_url, client_id, scope )
			int response = 0;
			if( sendReq ) {
				response = set_app_req(channel, server_url, client_id, scope );
				if( response != 0x9000 ) {
					// error
					Logd(TAG, " searchTokens error send params : 0x"+KryptoUtils.shortToHex(response));
					channel.close();
					return status;
				}
			}

			// search for token
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = SEARCH_TOKENS;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			byte respApdu [] = channel.transmit(buffer);
			if(respApdu ==null || respApdu.length<2) {
				throw new Exception("respApdu invalid");
			}
			
			status = bytesToInt(respApdu[respApdu.length-2],respApdu[respApdu.length-1]);
			
		} catch (Exception e) {
			Log.e(TAG, "searchTokens Error occured:", e);
		}
		
		// close channel if locally opened
		if(localChannel && channel!=null && !channel.isClosed()) {
			channel.close();
		}
		
		return status;
    	
    }

    // retrieve tokens from SIM, with a successful previous search
    static public TokensKeys get_tokens(Channel channel) {

    	// wait for debugger
        // android.os.Debug.waitForDebugger();

		BufferData buffer_data = new BufferData();
		try {

			byte seq = 0;
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = GET_TOKENS_KEY;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			Logd(TAG, "GET_TOKENS_KEY "+seq );
			while( receiveData( channel, buffer, buffer_data ) == true && buffer_data.sw1sw2 == 0x9014 ) {
				Logd(TAG, "GET_TOKENS_KEY answer: "+buffer_data.sw );
				Logd(TAG, "GET_TOKENS_KEY "+seq );
				seq++;
				if(seq<0) {
					// error, should not reach 0
					break;
				}
				buffer[IDX_P2] = (byte) seq;
			}
			
		} catch (Exception e) {
			Log.e(TAG, "Error occured:", e);
		}
		
		if (buffer_data.sw1sw2 == 0x9000 && buffer_data.buffer!=null) {
			try {
				return TokensKeys.makeFromBuffer(buffer_data.buffer);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return null;
	}

    // search for tokens in SIM, and if found return them
    public TokensKeys read_tokens (
    		String server_url,
    		String client_id,
    		String scope ) {

    	// wait for debugger
        // android.os.Debug.waitForDebugger();
    	
		Logd(TAG, "// read_tokens begin");

		Channel channel = null; 
		TokensKeys tk = null;

		try {

			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//read_tokens end : channel error");
				return tk;
			}
			
			int response = search_tokens(channel, server_url, client_id, scope, true);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "read_tokens error search : "+toHexa(response));
				channel.close();
				return tk;
			}

			// retrieve tokens
			tk = get_tokens(channel);
			
		} catch (Exception e) {
			Log.e(TAG, "read_tokens Error occured:", e);
		}
		
		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}

		return tk;
	}


    /*
     * SIM data reception buffer and status
     */
	static class BufferData {
		byte [] buffer;
		int offset=0;
		int seq=0;
		int sw1sw2=0;
		String sw;
		void set(byte sw1,byte sw2) {
			sw1sw2 = ((sw1 << 8) & 0x0000FF00) + (sw2 & 0x000000FF);
			sw = "0x"+KryptoUtils.byteToHex(sw1)+KryptoUtils.byteToHex(sw2);
		}
	}

	// convert an integer value to it string hexadecimal display
	static String toHexa(int n) {
		byte sw1 = (byte)( (n & 0x0000FF00) >> 8 );
		byte sw2 = (byte)(  n & 0x000000FF);
		return toHexa(sw1,sw2);
	}

	// convert a couple of byte values to it string hexadecimal display
	static String toHexa(byte b1, byte b2) {
		return "0x"+KryptoUtils.byteToHex(b1)+KryptoUtils.byteToHex(b2);
	}
	
	// convert a couple of byte values to a re-composed integer
	static int bytesToInt(byte b1, byte b2) {
		return ((b1 << 8) & 0x0000FF00) + (b2 & 0x000000FF);
	}
	
	// separate request for getting request object
	static boolean makeSeparateRO = true; 
	
    static final byte prefixSHA256[] = { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

	
	// get request object 
	public String getTimRequestObject(
			String server_url,
			String client_id,
			String scope,
			PublicKey serverPubKey
			) {
		
		JSONObject object = new JSONObject();

		Logd(TAG, "//getTimRequestObject begin");
		try {
			
			object.put("response_type", "code");
			object.put("scope", scope);
			object.put("redirect_uri", getRedirectUri());

			object.put("client_id", getClientId());
		
			JSONObject timJS = new JSONObject();
			timJS.put("app_id", new JSONObject().put("value", client_id));
			timJS.put("tim_app_key", new JSONObject().put("essential", true));
			object.put("tim", timJS);

			
			// make it sign by the SIM card
			String jwS = signTimSHA256(object.toString());
			Logd("JWS",jwS);

			// encrypt JWS request by JWE
			return KryptoUtils.encryptJWE(jwS.getBytes(), serverPubKey, null);
			
		} catch (Exception e) {
			Log.e(TAG, "// getTimRequestObject - error occured:", e);
		}
		
		return null;
	}
	
	private String signTimSHA256( String dataToSign ) {
		
		if( dataToSign == null || dataToSign.length()==0)
			return null;
		
		Channel channel = null;
		try {
			String dataToSign64 = KryptoUtils.encodeB64(dataToSign.getBytes("UTF8"));
	
			// get JWT
			String header64 = KryptoUtils.encodeB64(signHeader.getBytes());
			String toSign64 = header64+"."+dataToSign64;
			
			// make it sign by the SIM card
			
			// connect
			channel = initChannelToSIM();
			if ( channel == null ) {
				Logd(TAG, "// signTimSHA256 end : channel error");
				return null;
			}
	
			// compute sha256 hash
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
	        byte[] hash = digest.digest(toSign64.getBytes("UTF-8"));
	        int sha_length = hash.length+prefixSHA256.length;
	
			// make new buffer with size at first 2 bytes
			byte sendBytes[] = new byte[sha_length+2];
			sendBytes[0] = (byte)((sha_length&0x00FF00)>>8);
			sendBytes[1] = (byte)(sha_length&0x00FF);
			// copy data ( prefix sha 256 and hash )
	        System.arraycopy(prefixSHA256, 0, sendBytes, 2, prefixSHA256.length);
	        System.arraycopy(hash, 0, sendBytes, prefixSHA256.length+2, hash.length);
			
			// send request data (server_url, client_id, scope )
			int response = sendDataToSIM(channel, SET_ENCRYPT_DATA, sendBytes);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "signTimSHA256 error SET_ENCRYPT_DATA : "+toHexa(response));
				channel.close();
				return null;
			}
	
			// get crypted data as signature
			byte signBuff[] = getData(channel, GET_ENCRYPTED_TIM);
			channel.close();
			
			if ( signBuff != null && signBuff.length>0 ) {
				return toSign64+"."+KryptoUtils.encodeB64(signBuff);
			}
		} catch (Exception e) {
			Log.e(TAG, "// signTimSHA256 - error occured:", e);
		}

		if (channel != null && !channel.isClosed()) {
			channel.close();
		}
		return null;
	}

	
	// get TIM ID from SIM
	public String getClientId() {
		return getString( GET_TIM_ID );
	}

    static final private String TIM_redirect_uri = "http://tim/";
	public String getRedirectUri() {
		// TODO : for future use ...
		// return getString( GET_REDIRECT_URI );
		return TIM_redirect_uri ;
	}

	// get TIM secret from SIM
	private String getTimSecret() {
		return getString( GET_TIM_SECRET );
	}

	// request the SIM to generate new TIM app keys
	// and return tokens and new public key
	public TokensKeys genTimAppKey( OpenidConnectParams ocp ) {

		String status = genTimAppKey(ocp.m_server_url, ocp.m_client_id, ocp.m_scope, true);
		if( status!=null && status.compareToIgnoreCase("0x9000")==0) {
			// return tokens
			return read_tokens(ocp.m_server_url, ocp.m_client_id, ocp.m_scope);
		}
		Logd(TAG, "genTimAppKey failed : "+status);
		return null;
	}

	// request the SIM to generate new TIM app keys
	public static String genTimAppKey(
			String server_url, 
			String client_id, 
			String scope,
			boolean sendReq) {
        // android.os.Debug.waitForDebugger();
		
		Channel channel = null;
		byte[] respApdu = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

		Logd(TAG, "//genTimAppKey begin");
		try {
			
			channel = initChannelToSIM();

			if(channel==null) {
				Logd(TAG, "//genTimAppKey end : channel error");
				return null;
			}

			int response = search_tokens(channel, server_url, client_id, scope, sendReq);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "read_tokens error search : "+toHexa(response));
				channel.close();
				return null;
			}

			// search for tokens
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = SEARCH_TOKENS;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			Logd(TAG, "sending request search");
			respApdu = channel.transmit(buffer);

			if ( checkApduAndCloseChannelOnError(respApdu, channel) == false ) {
				return null;
			}
			
			// generate new key pair
			buffer[IDX_INS] = MAKE_DATA;
			buffer[IDX_P1]  = GEN_TIM_APP_KEY;
			
			Logd(TAG, "sending app key gen");
			respApdu = channel.transmit(buffer);

		} catch (Exception e) {
			Log.e(TAG, "// genTimAppKey - error occured:", e);
		}

		if (channel != null) {
			channel.close();
		}

		Logd(TAG, "//genTimAppKey end");
		if(respApdu!=null && respApdu.length >=2 ) {
			return toHexa(respApdu[respApdu.length-2],respApdu[respApdu.length-1]);
		}
		return null;
	}

	// send token data to be signed by the SIM with SHA256
	public static byte[] signTimAccessTokenSHA256(String dataToSign, Channel channel) {
		
		if( dataToSign == null || dataToSign.length()==0 || channel==null)
			return null;
		
		Logd(TAG, "// signDataSHA256 begin");
		try {
			// compute sha256 hash
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dataToSign.getBytes("UTF8"));
            int sha_length = hash.length+prefixSHA256.length;

			// make new buffer with size at first 2 bytes
			byte sendBytes[] = new byte[sha_length+2];
			sendBytes[0] = (byte)((sha_length&0x00FF00)>>8);
			sendBytes[1] = (byte)(sha_length&0x00FF);
			// copy data ( prefix sha 256 and hash )
            System.arraycopy(prefixSHA256, 0, sendBytes, 2, prefixSHA256.length);
            System.arraycopy(hash, 0, sendBytes, prefixSHA256.length+2, hash.length);

            // send data to sign
			int sw1sw2 = sendDataToSIM(channel, SET_ENCRYPT_DATA, sendBytes);
			if( sw1sw2  != 0x9000 ) {
				throw new Exception("signDataSHA256 error SET_ENCRYPT_DATA with code: "+sw1sw2);
			} else {
				// get crypted data as signature
				byte signBuff[] = getData(channel, GET_ENCRYPTED_TAK);
				
				if( signBuff == null || signBuff.length<1 ) {
					// error
					Logd(TAG, "signDataSHA256 getData error GET_ENCRYPTED_TAK");
					return null;
				}
				
				return signBuff;
			}
		} catch (Exception e) {
			Log.e(TAG, "// signDataSHA256 - error occured:", e);
		}

		Logd(TAG, "// signDataSHA256 end");
		return null;
	}
	
	public static String buildTimAccessToken(String tim_id, String client_id, String sub, String scope, String jwk) {
		// android.os.Debug.waitForDebugger();
        JSONObject jo = new JSONObject();
        try {
        	
	        JSONArray ja = new JSONArray();
	        // add subject
			jo.put("sub", sub);
			
			// prepare and add audience
			ja.put(tim_id);
			ja.put(client_id);
			jo.put("aud", ja);

			// add scope
			jo.put("scope", scope);
			
			// add times : delivery and expiration
			long now = Calendar.getInstance().getTimeInMillis() / 1000;
			jo.put("exp", ""+(now+TIM_ACCESS_TOKEN_TIMEOUT));
			jo.put("iat", ""+now);
			// jo.put("auth_time", ""+now);
			
			// add authorization party
			jo.put("azp", tim_id);
			
			// add jwk if specified
			if ( jwk!=null && jwk.length()>0 ) {
				jo.put("jwk", jwk);
			}
        } catch (Exception e) {
        	e.printStackTrace();
        }
        
        return jo.toString();
	}


	// generate a new signed TIM access token
	public String getNewTimToken(OpenidConnectParams ocp) {

		Channel channel = null; 
		TokensKeys tk = null;

		try {

			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "// getNewTimToken : channel error");
				return null;
			}
			
			int response = search_tokens(channel, ocp.m_server_url, ocp.m_client_id, ocp.m_scope, true);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "getNewTimToken error search : "+toHexa(response));
				channel.close();
				return null;
			}

			// retrieve tokens
			tk = get_tokens(channel);
			
			if( tk != null  &&  tk.id_token != null ) {
				// check expiration
				if ( tk.isRefreshTokenValid() ) {
					Token token = new Token(tk.id_token);
					
					// get TIM ID
					String tim_id = null;
					byte data[] = getData( channel, GET_TIM_ID );
					try {
						if(data!=null) {
							tim_id = new String(data);
						}
					} catch(Exception e) {
					}

					// generate new TIM access token
					String tim_access_token = buildTimAccessToken( tim_id, ocp.m_client_id, token.sub, ocp.m_scope, ocp.m_jwk );
					String header64 = KryptoUtils.encodeB64(signHeader.getBytes());
					String dataToSign = header64+"."+KryptoUtils.encodeB64(tim_access_token.getBytes());
					
					// get signature from SIM
					byte signed_data [] = signTimAccessTokenSHA256(dataToSign, channel);
			    	
					// close channel
					if( channel != null && !channel.isClosed()) {
						channel.close();
					}

					// if valid, return complete signed tim access token
					if( signed_data!=null && signed_data.length>0 ) {
				    	return dataToSign+"."+KryptoUtils.encodeB64(signed_data);
			    	}
				}
			}

		} catch (Exception e) {
			Log.e(TAG, "read_tokens Error occured:", e);
		}
		
		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}

		return null;
	}

	// delete tokens from a previous search of tokens
    public boolean delete_tokens(
    		String server_url,
			String client_id,
			String scope ) {

    	boolean bStatus = false;
    	Channel channel = null;
    	try {
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//delete_tokens end : channel error");
				return bStatus;
			}

			int response = search_tokens(channel, server_url, client_id, scope, true);
			if( response != 0x9000 ) {
				// error
				Logd(TAG, "//delete_tokens error search : "+toHexa(response));
				channel.close();
				return bStatus;
			}
			
			byte []respApdu = channel.transmit(new byte[] { TIM_CLA, STORE_DATA, DELETE_TOKENS_KEY, 0x00, 0x00 });
			String sw1sw2 = "";
			if(respApdu!=null && respApdu.length>2)
				sw1sw2 = toHexa(respApdu[respApdu.length-2],respApdu[respApdu.length-1]);
			else
				sw1sw2 = KryptoUtils.bytesToHex(respApdu);
			if( sw1sw2.compareToIgnoreCase("9000")==0 )
				bStatus = true;

    	} catch(Exception e) {
			Log.e(TAG, "read_tokens Error occured:", e);
    	}

		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}
    	
    	return bStatus;
    }

    public String getPrivateKeyJwt(String token_endpoint) {
		String privateKeyJwt = null;
        try {
            JSONObject jo = new JSONObject();
            String client_id = getClientId();
			jo.put("iss", client_id);
			jo.put("sub", client_id);
			jo.put("aud", token_endpoint);
			jo.put("jti", new BigInteger(130, new SecureRandom()).toString(32));
			long now = Calendar.getInstance().getTimeInMillis() / 1000;
			// expires in 3 minutes
			jo.put("exp", ""+(now+180));
		
			String dataToSign = jo.toString();
			
			if( dataToSign==null || dataToSign.length()==0) {
				return null;
			}

			// get signature from SIM
			privateKeyJwt = signTimSHA256(dataToSign);

        } catch (Exception e) {
        	e.printStackTrace();
        }
        
        return privateKeyJwt;
	}
	
    public String getClientSecretBasic() {
		String bearer = (getClientId()+":"+getTimSecret());
        return Base64.encodeToString(bearer.getBytes(),Base64.DEFAULT);
	}

/*
	// enhanced functions
   
    // reset ( clear ) TIM storage on SIM 
    static public String set_reset() {
    	Channel channel = null;
    	String status=null;
    	try {
			channel = initChannelToSIM();
			if(channel==null) {
				Logd(TAG, "//setReset end : channel error");
				return status;
			}

			byte []respApdu = channel.transmit(new byte[] { TIM_CLA, STORE_DATA, SET_RESET, 0x00, 0x00 });
			if(respApdu!=null && respApdu.length>2)
				status = "0x" + toHexa(respApdu[respApdu.length-2],respApdu[respApdu.length-1]);
			else
				status = "0x" + KryptoUtils.bytesToHex(respApdu); 

    	} catch(Exception e) {
    		e.printStackTrace();
    	}

		// close channel
		if( channel != null && !channel.isClosed()) {
			channel.close();
		}
    	
    	return status;
	}

    static public byte [] getMemoryData() {
    	Channel channel = null; 
		BufferData buffer_data = new BufferData();
		try {
			if(useSIM) {
				channel = initChannelToSIM();
				if(channel==null) {
					Logd(TAG, "//getMemoryData end : channel error");
					return null;
				}
			} else {
				Logd(TAG, "Create logical channel within the session...");
				Logd(TAG, "0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x00 0x00");
			}
			
			// search for token
			byte seq = 0;
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = GET_ALL;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			Logd(TAG, "getMemoryData "+seq );
			while( receiveData(channel,buffer,buffer_data, null) == true && buffer_data.sw1sw2 == 0x9014 ) {
				Logd(TAG, "getMemoryData "+seq );
				seq++;
				buffer[IDX_P2] = (byte) seq;
			}
			
		} catch (Exception e) {
			Log.e(TAG, "getMemoryData Error occured:", e);
		}
		
		if(channel!=null) {
			channel.close();
		}
		
		if (buffer_data.sw1sw2 == 0x9000 && buffer_data.buffer!=null) {
			try {
				return buffer_data.buffer;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return null;
    }

    static public byte [] getTokenKeyData() {
    	Channel channel = null; 
		BufferData buffer_data = new BufferData();
		try {
			if(useSIM) {
				channel = initChannelToSIM();
				if(channel==null) {
					Logd(TAG, "//getTokenKeyData end : channel error");
					return null;
				}
			} else {
				Logd(TAG, "Create logical channel within the session...");
				Logd(TAG, "0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x00 0x00");
			}
			
			// search for token
			byte seq = 0;
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = GET_TK_ALL;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			Logd(TAG, "getTokenKeyData "+seq );
			while( receiveData(channel,buffer,buffer_data, null) == true && buffer_data.sw1sw2 == 0x9014 ) {
				Logd(TAG, "getTokenKeyData "+seq );
				seq++;
				buffer[IDX_P2] = (byte) seq;
			}
			
		} catch (Exception e) {
			Log.e(TAG, "getTokenKeyData Error occured:", e);
		}
		
		if(channel!=null) {
			channel.close();
		}
		
		if (buffer_data.sw1sw2 == 0x9000 && buffer_data.buffer!=null) {
			try {
				return buffer_data.buffer;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return null;
    }
*/

	// get app request ( serveur, client_id, scope and return_uri )  
	public static byte[] getAppReq() {
		return getData(GET_APP_REQ);
	}
	
	// get data specified by command as P1 and GET_DATA as INS
	public static byte[] getData(byte command) {
    	Channel channel = null; 
		BufferData buffer_data = new BufferData();
		try {
			channel = initChannelToSIM();
			if(channel==null) {
				Log.i(TAG, "//getAppReq end : channel error");
				return null;
			}
			
			// search for token
			byte seq = 0;
			byte[] buffer = new byte[5];
			buffer[IDX_CLA]  = TIM_CLA;
			buffer[IDX_INS]  = GET_DATA;
			buffer[IDX_P1]   = command;
			buffer[IDX_P2]   = 0x00;
			buffer[IDX_LC]   = 0x00;
			
			Logd(TAG, "getAppReq "+seq );
			while( receiveData(channel,buffer,buffer_data) == true && buffer_data.sw1sw2 == 0x9014 ) {
				Logd(TAG, "getAppReq "+seq );
				seq++;
				buffer[IDX_P2] = (byte) seq;
			}
			
		} catch (Exception e) {
			Log.e(TAG, "getAppReq Error occured:", e);
		}
		
		if(channel!=null) {
			channel.close();
		}
		
		if (buffer_data.sw1sw2 == 0x9000 && buffer_data.buffer!=null) {
			try {
				return buffer_data.buffer;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return null;
    }

	// Basic SIM communication functions
	
	// initialize a communication channel to the SIM
	static private Channel initChannelToSIM() {
		try {
			Reader[] readers = seService.getReaders();
			if (readers.length < 1) {
				Logd(TAG, "//read from sim end");
				return null;
			}
	
			Logd(TAG, "Create Session from the first reader...");
			Session session = readers[0].openSession();
	
			Logd(TAG, "Create logical channel within the session...");
			Channel channel = session.openLogicalChannel( timSelectSIM );
			return channel;
		} catch ( Exception e) {
			
		}
		return null;
	}
	
	// check APDU response for 0x9000 then return true, if not, close channel and return false
	private static boolean checkApduAndCloseChannelOnError(byte respApdu[], Channel channel) {
		
		if( respApdu != null && respApdu.length >= 2 ) {
			if( respApdu[respApdu.length-2] == (byte)0x90 && respApdu[respApdu.length-1] == 0x00 ) {
				return true;
			}
		}

		// error
		if(channel!=null && !channel.isClosed())
			channel.close();
		
		String error = KryptoUtils.bytesToHex(respApdu);
		Logd(TAG, "checkApdu error : "+error);
		if( error.startsWith("6F") ) {
			Service.theService.toast("SIM CARD FAILURE "+error, 1);
		}

		return false;
	}

	// send STORE_DATA function with specified command and data buffer
	public static int sendDataToSIM(Channel channel, byte command, byte send_data[]) {

		int sw1sw2 = 0x6F00;
		
		if(send_data==null)
			return sw1sw2;
		
		int data_size = send_data.length;
		boolean localChannel = false;

    	try {
    		// initiate channel if not provided
			if(channel==null) {
				channel = initChannelToSIM();
				if(channel==null) {
					Logd(TAG, "//sendDataToSIM : channel error");
					return 0;
				}
				localChannel = true;
			}
			
			// send request data
			int seq = 0;
			while ((seq * BLOCK_SIZE) < data_size) {
				byte buffer[];
				// check if data to send is bigger than BLOCK_SIZE
				if (((seq + 1) * BLOCK_SIZE) <= data_size) {
					buffer = new byte[BLOCK_SIZE + HEADER_SIZE_WITH_DATA];
					buffer[IDX_CLA] = TIM_CLA;
					buffer[IDX_INS] = STORE_DATA;
					buffer[IDX_P1] = command;
					buffer[IDX_P2] = (byte) seq;
					buffer[IDX_LC] = (byte) BLOCK_SIZE;
	
					System.arraycopy(send_data, seq * BLOCK_SIZE, buffer, 5, BLOCK_SIZE);

				} else {
					// this is the last block to send
					int size = data_size - (seq * BLOCK_SIZE);
					buffer = new byte[size + HEADER_SIZE_WITH_DATA];
					buffer[IDX_CLA] = TIM_CLA;
					buffer[IDX_INS] = STORE_DATA;
					buffer[IDX_P1] = command;
					buffer[IDX_P2] = (byte) seq;
					buffer[IDX_LC] = (byte) size;
	
					System.arraycopy(send_data, seq * BLOCK_SIZE, buffer, 5, size);

				}
	
				Logd(TAG, "// Send request block " + seq);
				Logd(TAG, KryptoUtils.bytesToHex(buffer," 0x")+";");

				// transmit block
				byte[] respApdu = channel.transmit(buffer);
	
				// check response status
				sw1sw2 = readInt(respApdu, respApdu.length - 2);
				if ( sw1sw2 == 0x9000 || sw1sw2 == 0x9014 ) {
					// Success, check size
					if (((seq + 1) * BLOCK_SIZE) <= data_size) {
						// send next block
						seq++;
					} else {
						// last block sent
						return 0x9000;
					}
				} else {
					// error
					Logd(TAG, "sendDataToSIM error apdu : "+KryptoUtils.shortToHex(sw1sw2));
					break;
				}
			}
    	} catch (Exception e) {
			Logd(TAG,"sendDataToSIM exception: "+e);
    	}

    	// close channel if local
    	if(localChannel && channel!=null) {
			channel.close();
		}

		return sw1sw2;
	}

	// send GET_DATA function to retrieve data with a specified command
	// manage a reception buffer to group successive call of GET_DATA / command 
	public static byte [] getData( Channel channel, byte command ) {

		BufferData buffer_data = new BufferData();
		boolean localChannel = false;

		byte return_buffer[] = null; 
		
		Logd(TAG, "//read from sim begin");
		try {
    		// initiate channel if not provided
			if(channel==null) {
				channel = initChannelToSIM();
				if(channel==null) {
					Logd(TAG, "//getData end : channel error");
					return null;
				}
				localChannel = true;
			}

			// read data
			int seq = 0;
			byte[] buffer = new byte[HEADER_SIZE_NO_DATA];
			buffer[IDX_CLA] = TIM_CLA;
			buffer[IDX_INS] = GET_DATA;
			buffer[IDX_P1] = command;
			buffer[IDX_P2] = (byte) seq;
			buffer[IDX_LC] = 0x00;

			// iterate till all data is received 
			while( receiveData( channel, buffer, buffer_data ) == true && buffer_data.sw1sw2 == 0x9014 ) {
				seq++;
				buffer[3] = (byte) seq;
			}

			// check status response
			if (buffer_data.sw1sw2 == 0x9000 && buffer_data.buffer!=null) {
				return_buffer = buffer_data.buffer;
			}
			
			
		} catch(Exception e) {
			Logd(TAG,"getData exception: "+e);
		}

    	// close channel if local
		if(localChannel && channel!=null) {
			channel.close();
		}
		
		return return_buffer;
	}

	// retrieve binary data with specified command and convert to string
	public static String getString( byte command ) {
		byte data[] = getData( null, command );
		try {
			if(data!=null) {
				return new String(data);
			}
		} catch(Exception e) {
		}
		return null;
	}

	// retrieve data from SIM and return 0x9000 when all data is ready, 0x9014 when it's not finished or error
	static private boolean receiveData( Channel channel, byte [] send_buffer, BufferData buffer_data ) {
		if(send_buffer==null || buffer_data==null) return false;
		if( channel==null ) return false;
		
		int respApduLength = 0;
		try {
			
			Logd(TAG, "// receiveData : send request block " );
			Logd(TAG, KryptoUtils.bytesToHex(send_buffer," 0x")+";");

			// send request and read answer
			byte[] respApdu = channel.transmit(send_buffer);

			Logd(TAG, "// response apdu: "+ KryptoUtils.bytesToHex(respApdu," 0x"));
			
			
			respApduLength = respApdu != null ? respApdu.length : 0;
			if(respApduLength>=2) {
				// retrieve status word
				buffer_data.set(respApdu[respApdu.length-2],respApdu[respApdu.length-1]);
	
				// check status word value
				if( respApduLength >= 3 ) {
					if (	(buffer_data.sw1sw2 == 0x9014)
						||	(buffer_data.sw1sw2 == 0x9000) ) {
		
						
						// retrieve block size and sequence
						buffer_data.seq = (send_buffer[IDX_P2] & 0x00FF);
						
						// check sequence number
						if(buffer_data.seq==0) {
							// first sequence, retrieve total size
							int size = ((respApdu[0] << 8) & 0x0000FF00) + (respApdu[1] & 0x000000FF);
							// allocate space
							buffer_data.buffer = new byte[size];
		
							int block_size = respApdu.length - 4;
							// copy data to buffer
							System.arraycopy(respApdu, 2, buffer_data.buffer, buffer_data.offset, block_size);
							buffer_data.offset += block_size;
							
						} else {
							// for the second sequence and after ...
							int block_size = respApdu.length - 2;
							// copy data to buffer
							System.arraycopy(respApdu, 0, buffer_data.buffer, buffer_data.offset, block_size);
							buffer_data.offset += block_size;
						}
		
						if( buffer_data.buffer.length > buffer_data.offset) {
							// HACK: more to come
							buffer_data.sw1sw2 = 0x9014;
						}
					} else {
						buffer_data.buffer = respApdu;
						return false;
					}
				}
			} else {
				buffer_data.sw = "bad apdu";
			}

			return true;

		} catch(Exception e) {
			Logd(TAG, "receiveData - error occured:"+ e.getMessage());
		}
		
		return false;
	}

	// logging function, comment line to disable debug messages
	static void Logd(String tag, String msg) {
		Log.d(tag, msg);
	}
}
