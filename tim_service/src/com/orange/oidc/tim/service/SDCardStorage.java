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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.os.Environment;
import android.util.Base64;
import android.util.Log;

/**
 * 
 * SDCardStorage class
 * used to generate crypted and signed request objects
 * and to store tokens and generate tim access tokens
 * on phone SD card storage, path is to be defined
 *
 */
public class SDCardStorage extends TimSecureStorage {
	
	protected static final String TAG = "SD Storage";

	static private final String SAVE_DIR = "/openid-connect";
	static private final String SAVE_FILE = "TIM.data_php.txt";

	// final static String alg = "SHA1withRSA";
	final static String alg = "RS256";

	// JWS signature header
	static final String signHeader = "{\"alg\":\""+alg+"\",\"kid\":\"k2bdc\"}";

	static final int TIM_ACCESS_TOKEN_TIMEOUT = 180;

	// client_id and client_secret
	// here for demo only, must be stored in a secure element
	static final private String TIM_client_id = "TIM";
    static final private String TIM_secret = "timsecret";

    static final private String TIM_redirect_uri = "http://tim/";

	public String getClientId() {
		return TIM_client_id ;
	}

	public String getRedirectUri() {
		return TIM_redirect_uri ;
	}

	// local class used for storing params and tokens
	static class RequestTokenData {
		String lastVerifTime;
		String security_level;
		String server_url;
		String client_id;
		String scope;
		String serverScope;
		String redirect_uri;
		String id_token;
		String refresh_token;
		String expires;
		String jwk;
		
		public RequestTokenData clone() {
			RequestTokenData rt = new RequestTokenData ();
			rt.lastVerifTime  = lastVerifTime;
			rt.security_level = security_level;
			rt.server_url     = server_url;
			rt.client_id      = client_id;
			rt.scope          = scope;
			rt.serverScope    = serverScope;
			rt.redirect_uri   = redirect_uri;
			rt.id_token       = id_token;
			rt.refresh_token  = refresh_token;
			rt.expires        = expires;
			rt.jwk            = jwk;
			
			return rt;
		}

		public boolean read(BufferedReader reader) {
			try {
				lastVerifTime = reader.readLine();
				security_level = reader.readLine();
				server_url = reader.readLine();
				if( server_url == null ) return false;
				client_id = reader.readLine();
				scope = reader.readLine();
				serverScope = reader.readLine();
				redirect_uri = reader.readLine();
				id_token = reader.readLine();
				refresh_token = reader.readLine();
				expires = reader.readLine();
				jwk = reader.readLine();
				
				return true;
				
			} catch(Exception e) {
				e.printStackTrace();
			}
			return false;
		}
		
		public boolean write(BufferedWriter writer) {
			try {
				write(lastVerifTime,writer);
				write(security_level,writer);
				write(server_url,writer);
				write(client_id,writer);
				write(scope,writer);
				write(serverScope,writer);
				write(redirect_uri,writer);
				write(id_token,writer);
				write(refresh_token,writer);
				write(expires,writer);
				write(jwk,writer);
				
				return true;
				
			} catch(Exception e) {
				e.printStackTrace();
			}
			return false;
		}
		
		private void write(String s, BufferedWriter writer) throws IOException {
			if(s!=null && s.length()>0) {
				writer.append(s);
			}
			writer.newLine();
		}

		public RSAPrivateKey privKey() {
			if(jwk!=null && jwk.length()>0) {
				return KryptoUtils.privKeyFromJwk(jwk);
			}
			return null;
		}

		public PublicKey pubKey() {
			if(jwk!=null && jwk.length()>0) {
				return KryptoUtils.pubKeyFromJwk(jwk);
			}
			return null;
		}

		public String jwkPubKey() {
			if(jwk!=null && jwk.length()>0) {
				
				try {
					JSONObject jkw = new JSONObject(jwk).getJSONArray("keys").getJSONObject(0);
					JSONObject jk = new JSONObject();
					jk.put("kty", "RSA");

                    jk.put("kid", KryptoUtils.kidFromJwk(jwk));
					jk.put("e", jkw.getString("e"));
					
					jk.put("n", jkw.getString("n"));
		        	JSONArray ja = new JSONArray();
		        	ja.put(jk);
		        	JSONObject jo = new JSONObject();
		        	jo.put("keys", ja);
					return jo.toString();
				} catch (JSONException e) {
					e.printStackTrace();
				}
			}
			return null;
		}
		
		public boolean isExpired() {
			if( expires!=null && expires.length()>0 ) {
				long expireL = 0;
				try {
					expireL = Long.parseLong(expires);
				} catch(Exception e){}
				Calendar expCal = Calendar.getInstance();
				expCal.setTimeInMillis(expireL*1000);
				return expCal.before(Calendar.getInstance());
			}
			return true;
		}
	}
	
	// return true if equals content / null / empty ), false otherwise
	static boolean compareStrings(String a, String b) {
		if( a==null && b==null ) return true;
		if( a==null && b!=null && b.length()==0) return true;
		if( b==null && a!=null && a.length()==0) return true;
		try {
			return a.compareTo(b)==0;
		} catch(Exception e) {}
		return false;
	}
	
	// local class used for managing all tokens/params 
	static class RequestTokens {
		List<RequestTokenData> rtDatas = new ArrayList<RequestTokenData>();
		
		// private function to find token according to parameters
		protected RequestTokenData get(
				String server_url,
				String client_id,
				String scope,
				String redirect_uri ) {
			for(RequestTokenData rt : rtDatas) {
                // Logd(TAG,"RequestTokens get : server_url   "+server_url+" compare with "+ rt.server_url);
                // Logd(TAG,"RequestTokens get : client_id    "+client_id+" compare with "+ rt.client_id);
                // Logd(TAG,"RequestTokens get : scope        "+scope+" compare with "+ rt.scope);
                // Logd(TAG,"RequestTokens get : redirect_uri "+redirect_uri+" compare with "+ rt.redirect_uri);
				if(    rt != null
					&& compareStrings( rt.server_url, server_url )
					&& compareStrings( rt.client_id, client_id)
					&& compareStrings( rt.scope, scope)
					// && compareStrings( rt.redirect_uri, redirect_uri )
					) {
					return rt;
				}
			}
			
			return null;
		}

		// static function find token in local storage
		static public RequestTokenData find(
				String server_url,
				String client_id,
				String scope,
				String redirect_uri ) {
			RequestTokens rts = new RequestTokens();
			rts.load();
			return rts.get(server_url, client_id, scope, redirect_uri);
		}

		// update tokens
		static public void update_tokens(OpenidConnectParams ocp, String id_token, String refresh_token, String expires, String serverScope) {
			RequestTokens rts = new RequestTokens();
			rts.load();
			RequestTokenData rt = rts.get(ocp.m_server_url,ocp.m_client_id,ocp.m_scope,ocp.m_redirect_uri);
			if ( rt != null ) {
				rt.id_token = id_token;
				rt.refresh_token = refresh_token;
				rt.expires = expires;
				rt.serverScope = serverScope;
				rts.save();
			} else {
				Logd(TAG,"trying to update token not found");
			}
		}

		static public boolean deleteTokens(
				String server_url,
				String client_id,
				String scope,
				String redirect_uri ) {
			RequestTokens rts = new RequestTokens();
			rts.load();
			RequestTokenData rt = rts.get(server_url,client_id,scope,redirect_uri);
			if ( rt != null ) {
				rts.rtDatas.remove(rt);
				rts.save();
				return true;
			}
			return false;
		}

		static public void genTimAppKey (
				String server_url,
				String client_id,
				String scope,
				String redirect_uri ) {
			RequestTokens rts = new RequestTokens();
			rts.load();
			RequestTokenData rt = rts.get(server_url,client_id,scope,redirect_uri);
			if ( rt != null ) {
				// generate new keypair
				KeyPair kp = KryptoUtils.generateRsaKeyPair(512);
				if(kp!=null) {
					rt.jwk = KryptoUtils.getJwkPrivate(kp);
					rts.save();
				}
			}
		}
		
		static public void save_tokens(OpenidConnectParams ocp, String id_token, String refresh_token, String expires, String serverScope) {
			RequestTokens rts = new RequestTokens();
			rts.load();
			RequestTokenData rt = rts.get(ocp.m_server_url,ocp.m_client_id,ocp.m_scope,ocp.m_redirect_uri);
			
			// no use for demo
			/*
			if ( rt != null ) {
				// should not come here ...
				return;
			}
			*/
			if ( rt == null ) {
				rt = new RequestTokenData();
				rt.server_url    = ocp.m_server_url;
				rt.client_id     = ocp.m_client_id;
				rt.scope         = ocp.m_scope;
				rt.redirect_uri  = ocp.m_redirect_uri;
				rts.rtDatas.add(rt);
			}
			
			rt.serverScope   = serverScope;
			rt.id_token      = id_token;
			rt.refresh_token = refresh_token;
			rt.expires       = expires;

			Logd("SDStorage.save_tokens",rt.refresh_token);

			rts.save();
		}

		static public String getNewTimToken( OpenidConnectParams ocp ) {
			
			if(ocp==null)
				return null;
			
			RequestTokens rts = new RequestTokens();
			rts.load();
			RequestTokenData rt = rts.get(ocp.m_server_url,ocp.m_client_id,ocp.m_scope,ocp.m_redirect_uri);
			if ( rt != null ) {
				// check expiration
				if ( !rt.isExpired() ) {
					Token token = new Token(rt.id_token);
                    Logd(TAG,"Token not expired");
					// generate new TIM access token
					String tim_access_token = buildTimAccessToken( ocp.m_client_id, token.sub, rt.scope, ocp.m_jwk);
                    Logd(TAG,"built tim access token"+tim_access_token);
					String dataToSign=null;
					try {
						dataToSign = KryptoUtils.encodeB64(tim_access_token.getBytes("UTF-8"));
					} catch (UnsupportedEncodingException e) {
						e.printStackTrace();
					}
					
                    Logd(TAG,"Get crypto keys from jwk "+rt.jwk);
					RSAPrivateKey privKey = KryptoUtils.privKeyFromJwk(rt.jwk);
					PublicKey pubKey = KryptoUtils.pubKeyFromJwk(rt.jwk);
					
					// sign
			        // String signH = "{\"alg\":\""+alg+"\",\"kid\":\"k2bdc\"}";
                    String signH = "{\"alg\":\""+alg+"\",\"kid\":\""+ KryptoUtils.kidFromJwk(rt.jwk)+"\"}";
					String signed = KryptoUtils.signJWS(dataToSign, signH, alg, privKey);
					try {
						KryptoUtils.verifyJWS(signed, alg, pubKey, privKey);
					} catch(Exception e) {}
					return signed;
				}
                Logd(TAG,"Token expired");
			}
			return null;
		}
		
		private boolean load() {
			rtDatas.clear();
			String p = getSdFilePath();
			if(p==null) return false;
			
			File file = new File(p);

			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));
				RequestTokenData rt = new RequestTokenData();
				while( rt.read(reader) ) {
					rtDatas.add(rt);
					rt = new RequestTokenData();
				}
				reader.close();
				
			} catch(FileNotFoundException fnfe) {
				Logerr(TAG,"NO TOKEN FILE");
			} catch(Exception e) {
				e.printStackTrace();
			}
			
			return true;
		}

		private boolean save() {
			String p = getSdFilePath();
			if(p==null) return false;
			
			File file = new File(p);

			try {
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), "UTF-8"));
				for(int i=0; i<rtDatas.size(); i++) {
					RequestTokenData rt = rtDatas.get(i);
										rt.write(writer);
				}
				writer.flush();
				writer.close();
				
			} catch(Exception e) {
				Logd(TAG,"RequestTokens.save error");
				e.printStackTrace();
			}
			
			return true;
		}

		String getSdFilePath() {

			String path = null;
			String sdPath = Environment.getExternalStorageDirectory().toString();

			try {
				File f = new File(sdPath);
				if(f.exists()) {
					File dir = new File (f.getAbsolutePath() + SAVE_DIR);
					if( !dir.exists() ) {
						dir.mkdir();
					}
					if( dir.exists() ) {
						path = dir.getAbsolutePath();
						if(!path.endsWith("/")) {
							path += "/";
						}
						path += SAVE_FILE;
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			return path;
		}
	}
	
	// save tokens ( id and refresh ) to corresponding request 
	public String save_tokens(
			OpenidConnectParams ocp,
			String id_token,
			String refresh_token,
			String expires_in) {

		if(ocp!=null) {
			
			int expires = 0;
			try {
				expires = Integer.parseInt(expires_in);
			} catch (Exception e) {}

			Calendar cal = Calendar.getInstance();
			cal.setTimeZone(TimeZone.getTimeZone("GMT"));
			long timems  = cal.getTimeInMillis() + 1000*expires;
			RequestTokens.save_tokens(ocp, id_token, refresh_token, ""+(timems/1000), ocp.m_server_scope);
			return "";
		}
		return null;
	}

    // update tokens to specified app request
    public String update_tokens(OpenidConnectParams ocp, String id_token, String refresh_token, String expires) {
		if(ocp!=null) {
			RequestTokens.update_tokens(ocp, id_token, refresh_token, expires, ocp.m_server_scope);
			return "";
		}
		return null;
    }

    // search for tokens, and if found return them
    public TokensKeys read_tokens(
    		String server_url,
    		String client_id,
    		String scope ) {

    	RequestTokenData rt = RequestTokens.find(server_url, client_id, scope, null);
    	if ( rt != null ) {
    		TokensKeys tk = new TokensKeys();
    		tk.id_token = rt.id_token;
    		tk.refresh_token = rt.refresh_token;
    		tk.expires = rt.expires;
    		tk.privKey = rt.privKey();
    		tk.pubKey = (RSAPublicKey) rt.pubKey();
    		tk.jwkPub = rt.jwkPubKey();
    		tk.serverScope = rt.serverScope;
    		return tk;
    	}

		return null;
	}

    // get request object 
	public String getTimRequestObject(
			String server_url,
			String client_id,
			String scope,
			PublicKey serverPubKey
			) {

		JSONObject object = new JSONObject();
		try {
			object.put("response_type", "code");
			object.put("scope", scope);
			object.put("redirect_uri", getRedirectUri());

			object.put("client_id", TIM_client_id);
		
			JSONObject timJS = new JSONObject();
			timJS.put("app_id", new JSONObject().put("value", client_id));
			timJS.put("tim_app_key", new JSONObject().put("essential", true));
			object.put("tim", timJS);

			Logd(TAG, "getTimRequestObject : "+object.toString());
			
			String requestParam64 = KryptoUtils.encodeB64(object.toString().getBytes());

			// get JWT
			String jwS = KryptoUtils.signJWS(requestParam64, signHeader, alg, RsaKeyTim.privRsaKey);
			// jwS = object.toString();
			byte jwsBytes [] = jwS.getBytes();
			short paddLeft = (short) (jwsBytes.length % 16);
			if(paddLeft>0) {
				byte padd = (byte) ( 16 - paddLeft );
				byte jwsBytes_tmp [] = new byte [jwsBytes.length+padd];
				System.arraycopy(jwsBytes, 0, jwsBytes_tmp, 0, jwsBytes.length);
				for(byte i=0; i<padd; i++) {
					jwsBytes_tmp[(short)(jwsBytes.length+i)] = padd;
				}
				jwsBytes = jwsBytes_tmp;
			}

			// encrypt JWT request by JWE
			return KryptoUtils.encryptJWE(jwsBytes, serverPubKey, null);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}

	// request  to generate new TIM app keys
	// and return tokens and new public key
	public TokensKeys genTimAppKey( OpenidConnectParams ocp ) {
		RequestTokens.genTimAppKey(ocp.m_server_url, ocp.m_client_id, ocp.m_scope, ocp.m_redirect_uri);
		return read_tokens(ocp.m_server_url, ocp.m_client_id, ocp.m_scope);
	}

	public String getPrivateKeyJwt(String token_endpoint) {
		String privateKeyJwt = null;
        try {
            JSONObject jo = new JSONObject();
			jo.put("iss", TIM_client_id);
			jo.put("sub", TIM_client_id);
			jo.put("aud", token_endpoint);
			jo.put("jti", new BigInteger(130, new SecureRandom()).toString(32));
			long now = Calendar.getInstance().getTimeInMillis() / 1000;
			// expires in 3 minutes
			jo.put("exp", ""+(now+180));
		
			String dataToSign=null;
			try {
				dataToSign = KryptoUtils.encodeB64(jo.toString().getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			
			if( dataToSign!=null && dataToSign.length()>0) {
				// sign with TIM private key
	            String signH = "{\"alg\":\""+alg+"\"}";
	            privateKeyJwt = KryptoUtils.signJWS(dataToSign, signH, alg, RsaKeyTim.privRsaKey);
			}

        } catch (Exception e) {
        	e.printStackTrace();
        }
        
        return privateKeyJwt;
	}
	
	public String getClientSecretBasic() {
		
		String bearer = (TIM_client_id+":"+TIM_secret);
        return Base64.encodeToString(bearer.getBytes(),Base64.DEFAULT);
	}

	// build a json string to represent a tim access token
	public static String buildTimAccessToken(String client_id, String sub, String scope, String jwk) {
		// android.os.Debug.waitForDebugger();
        JSONObject jo = new JSONObject();
        try {
        	
        	String tim_id = TIM_client_id;
        	
	        // add subject
			jo.put("sub", sub);
			
			// prepare and add audience
	        JSONArray ja = new JSONArray();
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
	public String getNewTimToken( OpenidConnectParams ocp ) {
		return RequestTokens.getNewTimToken(ocp);
	}

	public boolean delete_tokens(
			String serverUrl,
			String client_id,
			String scope ) {
		return RequestTokens.deleteTokens(serverUrl, client_id, scope, null);
	}
	
	static void Logd(String tag, String msg) {
		if(tag==null) tag = "unknown";
		if(msg==null) msg = "unknown";
		Log.d(tag, msg);
	}

	static void Logerr(String tag, String msg) {
		if(tag==null) tag = "unknown";
		if(msg==null) msg = "unknown";
		Log.e(tag, msg);
	}

}
