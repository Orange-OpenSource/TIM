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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.PublicKey;
import java.security.cert.CertificateException;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;

import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;

public class HttpOpenidConnect {
    protected static final String TAG = "HttpOpenidConnect";
    static final String COOKIES_HEADER = "Set-Cookie";
	
	final static String openIdConfigurationUrl = ".well-known/openid-configuration";
	
	// input parameters
    OpenidConnectParams mOcp; 

    // client_secret_basic (false ) or private key jwt ( true )
    boolean mUsePrivateKeyJWT = true;

    // generic tim secure storage to sign request
    static TimSecureStorage secureStorage = null;

    // constructors
    public HttpOpenidConnect() {}
    public HttpOpenidConnect(OpenidConnectParams ocp) {
	    init(ocp);
    }
   
    // initialization
    public void init(OpenidConnectParams ocp) {
	    mOcp = new OpenidConnectParams(ocp);
        if(mOcp.m_server_url!=null && !mOcp.m_server_url.endsWith("/")) {
    	    mOcp.m_server_url += "/";
        }
    }
   
    // convert OpenidConnectParams to a HTTP POST string
    public String getPostParams() {
		List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(7);
		nameValuePairs.add(new BasicNameValuePair("grant_type", "code"));
		if(mOcp!=null) {
			// openid specific
			if (!isEmpty(mOcp.m_response_type))
				nameValuePairs.add(new BasicNameValuePair("response_type", mOcp.m_response_type));
			if (!isEmpty(mOcp.m_scope))
				nameValuePairs.add(new BasicNameValuePair("scope", mOcp.m_scope));
			if (!isEmpty(mOcp.m_state))
				nameValuePairs.add(new BasicNameValuePair("state", mOcp.m_state));
			if (!isEmpty(mOcp.m_nonce))
				nameValuePairs.add(new BasicNameValuePair("nonce", mOcp.m_nonce));
			if (!isEmpty(mOcp.m_redirect_uri))
				nameValuePairs.add(new BasicNameValuePair("redirect_uri", mOcp.m_redirect_uri));
			if (!isEmpty(mOcp.m_client_id))
				nameValuePairs.add(new BasicNameValuePair("client_id", mOcp.m_client_id));
			
		}
		// nameValuePairs.add(new BasicNameValuePair("prompt", "login"));
		
		return getQuery(nameValuePairs);
    }
   
    // write post params to an output stream
	String writePostParams(OutputStream os, String postParams) {

		try {
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter( os, "UTF-8"));
			writer.write(postParams);
			writer.flush();
			writer.close();
			return postParams;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	
	// return true is string is null or empty, false otherwise
    private static boolean isEmpty(String s) {
    	if(s==null || s.length()==0)
    		return true;
    	return false;
    }

    // connect to an oidc server
	public boolean getTokens (
			Context ctx,
			String id,
			boolean useTim,
			String login ) {

		if( mOcp == null ) return false;

		try {

			String requestObject = null;
			String authorization_endpoint = null;
			try {
				
				// retrieve openid config
				JSONObject json = getHttpJSON(mOcp.m_server_url+openIdConfigurationUrl);
				if( json == null ) {
	                Logd(TAG,"could not get openid-configuration on server : "+mOcp.m_server_url);
					return false;
				}

				// get authorization end_point
				authorization_endpoint = json.optString("authorization_endpoint");

				if(useTim) {
					// get jwks_uri of the server
					String jwks_uri = json.optString("jwks_uri");
					if( jwks_uri==null || jwks_uri.length()<1) {
		                Logd(TAG,"could not get jwks_uri from openid-configuration on server : "+mOcp.m_server_url);
						return false;
					}
					
					// get jwks
					String jwks = getHttpString(jwks_uri);
					if(jwks==null || jwks.length()<1) {
		                Logd(TAG,"could not get jwks_uri content from : "+jwks_uri);
						return false;
					}
					
					// extract public key
					PublicKey serverPubKey = KryptoUtils.pubKeyFromJwk(jwks);
					if(serverPubKey==null) {
		                Logd(TAG,"could not extract public key from jwk : "+jwks);
						return false;
					}
				
					// get tim request object
					requestObject = secureStorage.getTimRequestObject(mOcp.m_server_url,
							mOcp.m_client_id, mOcp.m_scope, serverPubKey);
	                Logd(TAG,"secureStorage requestObject : "+requestObject);
				}
			} catch (Exception ee) {
				// error generating request object
				ee.printStackTrace();
				return false;
			}

			// build post parameters
			List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(7);
			nameValuePairs.add(new BasicNameValuePair("redirect_uri",  mOcp.m_redirect_uri));
			nameValuePairs.add(new BasicNameValuePair("response_type", "code"));
			nameValuePairs.add(new BasicNameValuePair("scope",         mOcp.m_scope));
			if(useTim)
				nameValuePairs.add(new BasicNameValuePair("client_id",     secureStorage.getClientId()));
			else
				nameValuePairs.add(new BasicNameValuePair("client_id",     mOcp.m_client_id));
			nameValuePairs.add(new BasicNameValuePair("nonce",         mOcp.m_nonce));
			if( !isEmpty(requestObject) ) {
				nameValuePairs.add(new BasicNameValuePair("request",   requestObject));
			}
			nameValuePairs.add(new BasicNameValuePair("prompt",        "consent"));

			// get URL encoded string from list of key value pairs
			String postParams = getQuery(nameValuePairs);

			// launch webview

			// init intent
			Intent intent = new Intent(Intent.ACTION_VIEW);
			intent.setClass(ctx, WebViewActivity.class);

			// prepare request parameters
			intent.putExtra("id", id);

			intent.putExtra("server_url",   authorization_endpoint);
			intent.putExtra("redirect_uri", mOcp.m_redirect_uri);
			intent.putExtra("client_id",    mOcp.m_client_id);
			if (login != null)
				intent.putExtra("login", login);

			if (useTim) {
				intent.putExtra("use_tim", true);
			} else {
				intent.putExtra("client_secret", mOcp.m_client_secret);
			}
			intent.putExtra("postParams", postParams);

			intent.setFlags(
					  Intent.FLAG_ACTIVITY_NEW_TASK
					| Intent.FLAG_ACTIVITY_SINGLE_TOP
					| Intent.FLAG_ACTIVITY_NO_ANIMATION);

			// display webview
			ctx.startActivity(intent);
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	// always verify the host - dont check for certificate
	final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

	/**
	 * WARNING : only use in development environment,
	 * DO NOT USE in production or commercial environments !!!
	 * Trust every server - do not check for any certificate
	 */
	private static void trustAllHosts() {
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			@Override
			public void checkClientTrusted(
					java.security.cert.X509Certificate[] x509Certificates,
					String s) throws CertificateException {

			}

			@Override
			public void checkServerTrusted(
					java.security.cert.X509Certificate[] x509Certificates,
					String s) throws CertificateException {

			}

			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return new java.security.cert.X509Certificate[] {};
			}

		} };

		// Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection
					.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

    // get a HTTP connector
   static public HttpURLConnection getHUC(String address) {
       HttpURLConnection http = null;
       try {
           URL url = new URL(address);

           if (url.getProtocol().equalsIgnoreCase("https")) {
        	   // only use trustAllHosts and DO_NOT_VERIFY in development process
               trustAllHosts();
               HttpsURLConnection https = (HttpsURLConnection) url.openConnection();
               https.setHostnameVerifier(DO_NOT_VERIFY);
               http = https;
           } else {
               http = (HttpURLConnection) url.openConnection();
           }
       } catch (Exception e) {
           e.printStackTrace();
       }
       return http;
   }

   // get an URL encoded string from a list of keypair value 
   private static String getQuery(List<NameValuePair> params) {
       StringBuilder result = new StringBuilder();
       boolean first = true;

       try {
	       for (NameValuePair pair : params)
	       {
	           if (first)
	               first = false;
	           else
	               result.append("&");
	
	           if( pair != null ) {
	        	   String name  = pair.getName();
	        	   String value = pair.getValue();
	        	   if( name!=null && value != null ) {
			           result.append(URLEncoder.encode(pair.getName(), "UTF-8"));
			           result.append("=");
			           result.append(URLEncoder.encode(pair.getValue(), "UTF-8"));
	        	   }
	           }
	       }
       } catch ( Exception e ) {
    	   e.printStackTrace();
       }

       return result.toString();
   }

	public static String convertStreamToString(InputStream is) {
		/*
		 * To convert the InputStream to String we use the
		 * BufferedReader.readLine() method. We iterate until the BufferedReader
		 * return null which means there's no more data to read. Each line will
		 * appended to a StringBuilder and returned as String.
		 */
		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		StringBuilder sb = new StringBuilder();

		String line = null;
		try {
			while ((line = reader.readLine()) != null) {
				sb.append(line + "\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return sb.toString();
	}

	// called from webview after authorization code is granted
	public String doRedirect(String urlRedirect, boolean useTim) {
        // android.os.Debug.waitForDebugger();
        try {
            // with server phpOIDC, check for '#'
            if((urlRedirect.startsWith(mOcp.m_redirect_uri+"?")) || (urlRedirect.startsWith(mOcp.m_redirect_uri+"#")))
            {
                String []params = urlRedirect.substring(mOcp.m_redirect_uri.length()+1).split("&");
                String code = "";
                String state = "";
                String state_key = "state"; 
                for (int i=0; i<params.length; i++)
                {
                    String param = params[i];
                    int idxEqual = param.indexOf('=');
                    if(idxEqual>=0)
                    {
                        String key = param.substring(0, idxEqual);
                        String value = param.substring(idxEqual+1);
                        if(key.startsWith("code")) code = value;
                        if(key.startsWith("state")) state = value;
                        if(key.startsWith("session_state")) {
                        	state = value;
                        	state_key = "session_state";
                        }
                    }
                }

                // display code and state
                Logd(TAG,"doRedirect => code: "+code+" / state: "+state);
                
                // doRepost(code,state);
                if( code.length() > 0  ) {
                	
            		// get token_endpoint endpoint
            		String token_endpoint = getEndpointFromConfigOidc("token_endpoint",mOcp.m_server_url);
            		if( isEmpty( token_endpoint ) ) {
                        Logd(TAG,"logout : could not get token_endpoint on server : "+mOcp.m_server_url);
            			return null;
            		}

                    List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
                    HttpURLConnection huc = getHUC(token_endpoint);
                    huc.setInstanceFollowRedirects(false);

                    if(useTim) {
                        if( mUsePrivateKeyJWT ) {
                    		nameValuePairs.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                    		String client_assertion = secureStorage.getPrivateKeyJwt(token_endpoint);
                    		Logd(TAG,"client_assertion: "+client_assertion);
                    		nameValuePairs.add(new BasicNameValuePair("client_assertion", client_assertion));
                        } else {
                        	huc.setRequestProperty("Authorization","Basic "+secureStorage.getClientSecretBasic());
                        }
                    } else {
                        String authorization = (mOcp.m_client_id+":"+mOcp.m_client_secret);
                        authorization = Base64.encodeToString(authorization.getBytes(),Base64.DEFAULT);
                        huc.setRequestProperty("Authorization","Basic "+authorization);
                    }

                    huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
                    
                    huc.setDoOutput(true);
                    huc.setChunkedStreamingMode(0);

                    OutputStream os = huc.getOutputStream();
                    OutputStreamWriter out = new OutputStreamWriter(os, "UTF-8");
                    BufferedWriter writer = new BufferedWriter(out);

                    nameValuePairs.add(new BasicNameValuePair("grant_type", "authorization_code"));
                    nameValuePairs.add(new BasicNameValuePair("code", code));
                    nameValuePairs.add(new BasicNameValuePair("redirect_uri", mOcp.m_redirect_uri));
                    if( state!=null && state.length()>0 )
                    	nameValuePairs.add(new BasicNameValuePair(state_key, state));

        			// write URL encoded string from list of key value pairs
                    writer.write(getQuery(nameValuePairs));
                    writer.flush();
                    writer.close();
                    out.close();
                    os.close();

                    Logd(TAG, "doRedirect => before connect");
                    huc.connect();
                    int responseCode = huc.getResponseCode();
                    System.out.println("2 - code "+responseCode);
                    Log.d(TAG, "doRedirect => responseCode "+responseCode);
                    InputStream in = null;
                    try{
                        in = new BufferedInputStream(huc.getInputStream());
                    }
                    catch (IOException ioe) {
                        sysout("io exception: "+huc.getErrorStream());
                    }
                    if(in!=null) {
                        String result= convertStreamToString(in);
                        // now you have the string representation of the HTML request
                        in.close();

                        Logd(TAG,"doRedirect: "+result);

                        // save as static for now
                        return result;
                        
                    } else {
                    	Logd(TAG,"doRedirect null");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
	
    // get TIM user info
    static String getTimUserInfo( String server_url, String tim_access_token) {
        // android.os.Debug.waitForDebugger();
    	// default result
        String result = null;

    	// check if server is valid
    	if( isEmpty(server_url) || isEmpty(tim_access_token) ) {
            Logd(TAG, "getTimUserInfo no server url or tim_access_token");
    		return null;
    	}
		
    	if(!server_url.endsWith("/")) server_url += "/";

		// get user info endpoint
		String userinfo_endpoint = getEndpointFromConfigOidc( "userinfo_endpoint", server_url );
		if( isEmpty(userinfo_endpoint) ) {
            Logd(TAG,"getTimUserInfo : could not get endpoint on server : "+server_url);
			return null;
		}

        // build connection
        HttpURLConnection huc = getHUC(userinfo_endpoint);
        huc.setInstanceFollowRedirects(false);
        huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");

   		huc.setRequestProperty("Authorization","Bearer "+tim_access_token);
		Logd("getTimUserInfo","bearer: "+tim_access_token);

        try {
	        // try to establish connection 
           huc.connect();
           // get result
           int responseCode = huc.getResponseCode();
           Logd(TAG, "getTimUserInfo 2 response: "+responseCode);
           
           // if 200, read http body
           if ( responseCode == 200 ) {
               InputStream is = huc.getInputStream();
               result= convertStreamToString(is);
               is.close();
               Logd(TAG, "getTimUserInfo 2 result: "+result);
           } else {
        	   // result = "response code: "+responseCode;
           }
           
           // close connection
           huc.disconnect();
	        
		} catch (Exception e) {
            Log.e(TAG, "getTimUserInfo FAILED");
			e.printStackTrace();
		}
    	
        return result;
    }

    // get user info
    static String getUserInfo( String server_url, String access_token ) {
        // android.os.Debug.waitForDebugger();
    	
    	// check if server is valid
    	if( isEmpty(server_url) || isEmpty(access_token) ) {
    		return null;
    	}

    	String userinfo_endpoint = getEndpointFromConfigOidc( "userinfo_endpoint", server_url );
		if( isEmpty(userinfo_endpoint) ) {
            Logd(TAG,"getUserInfo : could not get endpoint on server : "+server_url);
			return null;
		}
    	
        Logd(TAG, "getUserInfo : "+userinfo_endpoint);
    	// build connection
        HttpURLConnection huc = getHUC(userinfo_endpoint);
        huc.setInstanceFollowRedirects(false);
        // huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");

   		huc.setRequestProperty("Authorization","Bearer "+access_token);

    	// default result
        String result = null;

        try {
	        // try to establish connection 
           huc.connect();
           // get result
           int responseCode = huc.getResponseCode();
           Logd(TAG, "getUserInfo 2 response: "+responseCode);
           
           // if 200, read http body
           if ( responseCode == 200 ) {
               InputStream is = huc.getInputStream();
               result= convertStreamToString(is);
               is.close();
           }
           
           // close connection
           huc.disconnect();
	        
		} catch (Exception e) {
	        Logd(TAG, "getUserInfo failed");
			e.printStackTrace();
		}
    	
        return result;
    }
    
    // refresh token
    String refreshToken( String refresh_token ) {
        // android.os.Debug.waitForDebugger();

    	// check initialization
    	if(mOcp == null || isEmpty(mOcp.m_server_url))
    	    return null;
    	 
    	// nothing to do
    	if( isEmpty(refresh_token)) return null;
    	
    	String postUrl = mOcp.m_server_url+"token";

    	// set up connection
        HttpURLConnection huc = getHUC(postUrl);
        huc.setDoOutput(true);
        huc.setInstanceFollowRedirects(false);
        huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");

        // prepare parameters
        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(7);
		nameValuePairs.add(new BasicNameValuePair("client_id", mOcp.m_client_id));
		nameValuePairs.add(new BasicNameValuePair("client_secret", mOcp.m_client_secret));

		nameValuePairs.add(new BasicNameValuePair("grant_type", "refresh_token"));
		nameValuePairs.add(new BasicNameValuePair("refresh_token", refresh_token));
		if ( !isEmpty(mOcp.m_scope) )
			nameValuePairs.add(new BasicNameValuePair("scope", mOcp.m_scope));

        try {
        	// write parameters to http connection
	        OutputStream os = huc.getOutputStream();
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
					os, "UTF-8"));
			// get URL encoded string from list of key value pairs
			String postParam = getQuery(nameValuePairs);
			Logd("refreshToken","url: "+postUrl);
			Logd("refreshToken","POST: "+postParam);
			writer.write(postParam);
			writer.flush();
			writer.close();
	        os.close();

	        // try to connect
	        huc.connect();
	        // connexion status
            int responseCode = huc.getResponseCode();
            Logd(TAG, "refreshToken response: "+responseCode);

            // if 200 - OK, read the json string
            if ( responseCode == 200 ) {
               sysout("refresh_token - code "+responseCode);
               InputStream is = huc.getInputStream();
               String result= convertStreamToString(is);
               is.close();
               huc.disconnect();

               Logd("refreshToken","result: "+result);
               sysout("refresh_token - content: "+result);

               return result;
            }
            huc.disconnect();
        } catch ( Exception e) {
        	e.printStackTrace();
        }

		return null;
    }
    
    // refresh token with TIM
    String refreshTokenWithTIM() {
        // android.os.Debug.waitForDebugger();

    	// check initialization
    	if(mOcp == null || isEmpty(mOcp.m_server_url))
    	    return null;

		// get refresh endpoint
		String token_endpoint = getEndpointFromConfigOidc("token_endpoint",mOcp.m_server_url);
		if( isEmpty(token_endpoint) ) {
            Logd(TAG,"logout : could not get token_endpoint on server : "+mOcp.m_server_url);
			return null;
		}

    	// set up connection
        HttpURLConnection huc = getHUC(token_endpoint);
        huc.setDoOutput(true);
        huc.setInstanceFollowRedirects(false);
        huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");

        // generate new RSA keys by SIM
        TokensKeys tk = secureStorage.genTimAppKey( mOcp );

        if ( tk == null ) {
        	// no token key found
        	return null;
        }
        
        // check value of refresh token
        if( isEmpty(tk.refresh_token) ) {
        	// nothing to do
            Log.d("refreshTokenWithTIM","refresh_token null or empty");
        	return null;
        }
        
        // prepare parameters
        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(7);

        // add authentication assertion
        if( mUsePrivateKeyJWT ) {
        	String pkj = secureStorage.getPrivateKeyJwt(token_endpoint);
        	if( pkj !=null && pkj.length()>0 ) {
	    		nameValuePairs.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
	    		nameValuePairs.add(new BasicNameValuePair("client_assertion", pkj));
        	}
        } else {
        	String csb = secureStorage.getClientSecretBasic();
        	if( csb !=null && csb.length()>0 ) {
        		huc.setRequestProperty("Authorization","Basic "+csb);
        	}
        }
        

        String clientId = secureStorage.getClientId();
        nameValuePairs.add(new BasicNameValuePair("client_id", clientId));
		nameValuePairs.add(new BasicNameValuePair("grant_type", "refresh_token"));
		nameValuePairs.add(new BasicNameValuePair("refresh_token", tk.refresh_token));
		if ( !isEmpty(tk.serverScope) ) {
			nameValuePairs.add(new BasicNameValuePair("scope", tk.serverScope));
		} else if ( !isEmpty(mOcp.m_scope) ) {
			nameValuePairs.add(new BasicNameValuePair("scope", mOcp.m_scope));
		}


		// add public key to request
		nameValuePairs.add(new BasicNameValuePair("tim_app_key", tk.jwkPub));

        try {
        	// write parameters to http connection
	        OutputStream os = huc.getOutputStream();
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
					os, "UTF-8"));
			// get URL encoded string from list of key value pairs
			String postParam = getQuery(nameValuePairs);
			Logd("refreshTokenWithTIM","url: "+token_endpoint);
			Logd("refreshTokenWithTIM","POST: "+postParam);
			writer.write(postParam);
			writer.flush();
			writer.close();
	        os.close();

	        // try to connect
	        huc.connect();
	        // connexion status
            int responseCode = 0;
            try {
                // Will throw IOException if server responds with 401.
            	responseCode = huc.getResponseCode(); 
            } catch (IOException e) {
            	e.printStackTrace();
                // Will return 401, because now connection has the correct internal state.
                responseCode = huc.getResponseCode(); 
            }
            
            Logd(TAG, "refreshTokenWithTIM response: "+responseCode);

            // if 200 - OK, read the json string
            if ( responseCode == 200 ) {
               sysout("refreshTokenWithTIM - code "+responseCode);
               InputStream is = huc.getInputStream();
               String result= convertStreamToString(is);
               is.close();
               huc.disconnect();

               Logd("refreshTokenWithTIM","result: "+result);
               sysout("refreshTokenWithTIM - content: "+result);
               
               // TODO : verify TIM app key is correct
               
               return result;
            } else if( responseCode == 401 ) {
    			// remove entry
                Logd("refreshTokenWithTIM","got 401, remove entry");
   				secureStorage.delete_tokens(mOcp.m_server_url, mOcp.m_client_id, mOcp.m_scope);
    		}
            huc.disconnect();
        } catch ( Exception e) {
        	e.printStackTrace();
        }
		
		return null;

    }
    
    /**
     * Apply normalization rules to the identifier supplied by the End-User 
     * to determine the Resource and Host. Then make an HTTP GET request to
     * the host's WebFinger endpoint to obtain the location of the requested 
     * service
     * return the issuer location ("href")
     * @param user_input , domain
     * @return
     */
    
	public static String webfinger ( String userInput, String serverUrl ) {
        // android.os.Debug.waitForDebugger();

		String result = ""; // result of the http request (a json object
							// converted to string)
		String postUrl = "";
		String host = null;
		String href = null;

		// URI identifying the type of service whose location is being requested
		final String rel = "http://openid.net/specs/connect/1.0/issuer";

		if ( !isEmpty(userInput) ) {

			try {
				// normalizes this URI's path
				URI uri = new URI(userInput).normalize();
				String[] parts = uri.getRawSchemeSpecificPart().split("@");

				if ( !isEmpty(serverUrl) ) {
					// use serverUrl if specified
					if(serverUrl.startsWith("https://")) {
						host = serverUrl.substring(8);
					} else if(serverUrl.startsWith("http://")) {
						host = serverUrl.substring(7);
					} else {
						host = serverUrl;
					}
				} else  if (parts.length > 1) {
					// the user is using an E-Mail Address Syntax
					host = parts[parts.length - 1];
				} else { 
					// the user is using an other syntax
					host = uri.getHost();
				}

				// check if host is valid
				if (host == null) {
					return null;
				}

				if(!host.endsWith("/"))
					host += "/";
				postUrl = "https://" + host + ".well-known/webfinger?resource=" + userInput + "&rel=" + rel;

				// log the request
				Logd(TAG, "Web finger request\n GET " + postUrl + "\n HTTP /1.1" + "\n Host: " + host);
				// Send an HTTP get request with the resource and rel parameters
				HttpURLConnection huc = getHUC(postUrl);
				huc.setDoOutput(true);
				huc.setRequestProperty("Content-Type", "application/jrd+json");
				huc.connect();

				try {

					int responseCode = huc.getResponseCode();
					Logd(TAG, "webfinger responseCode: " + responseCode);
					// if 200, read http body
					if (responseCode == 200) {
						InputStream is = huc.getInputStream();
						result = convertStreamToString(is);
						is.close();
						Logd(TAG, "webfinger result: " + result);

						// The response is a json object and the issuer location
						// is returned as the value of the href member
						// a links array element with the rel member value
						// http://openid.net/specs/connect/1.0/issuer
						JSONObject jo = new JSONObject(result);
						JSONObject links = jo.getJSONArray("links").getJSONObject(0);
						href = links.getString("href");
						Logd(TAG, "webfinger reponse href: " + href);

					} else {
						// why the request didn't succeed
						href = huc.getResponseMessage();
					}

					// close connection
					huc.disconnect();
				} catch (IOException ioe) {
					Logd(TAG, "webfinger io exception: " + huc.getErrorStream());
					ioe.printStackTrace();
				}

			} catch (Exception e) {
				e.printStackTrace();
			}

		} else {
			// the user_input is empty
			href = "no identifier detected!!\n";
		}
		return href;
	}
	
	// call revoke_logout access point on server 
	public static boolean logout( String server_url, String tim_access_token ) {
		
		if( isEmpty(server_url) ) {
            Logd(TAG, "logout failed : no server url");
    		return false;
    	}
		
		// get revoke_logout endpoint
		String revoke_logout_endpoint = getEndpointFromConfigOidc( "revoke_logout_endpoint", server_url );
		if( isEmpty(revoke_logout_endpoint) ) {
            Logd(TAG,"logout : could not get revoke_logout_endpoint on server : "+server_url);
			return false;
		}
		
        // set up connection
        HttpURLConnection huc = getHUC(revoke_logout_endpoint);
        huc.setInstanceFollowRedirects(false);

        huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        
        huc.setDoOutput(true);
        huc.setChunkedStreamingMode(0);
        // prepare parameters
        List<NameValuePair> nameValuePairs = null;
        if(tim_access_token!=null && tim_access_token.length()>0) {
        	nameValuePairs = new ArrayList<NameValuePair>(1);
        	nameValuePairs.add(new BasicNameValuePair("tat", tim_access_token));
        }
		
        try {
        	// write parameters to http connection
        	if( nameValuePairs != null ) {
		        OutputStream os = huc.getOutputStream();
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
						os, "UTF-8"));
				// get URL encoded string from list of key value pairs
				String postParam = getQuery(nameValuePairs);
				Logd("Logout","url: "+revoke_logout_endpoint);
				Logd("Logout","POST: "+postParam);
				writer.write(postParam);
				writer.flush();
				writer.close();
		        os.close();
        	}

	        // try to connect
	        huc.connect();
	        // connection status
            int responseCode = huc.getResponseCode();
            Logd(TAG, "Logout response: "+responseCode);
            // if 200 - OK
            if ( responseCode == 200 ) {
                return true;
            }
            huc.disconnect();
        } catch ( Exception e) {
        	e.printStackTrace();
        }
		return false;
	}
	
	// call end_session endpoint on server
	public boolean logout( String server_url ) {

		if( isEmpty(server_url)  ) {
            Logd(TAG, "revokSite no server url");
    		return false;
    	}

    	if(!server_url.endsWith("/")) server_url += "/";

		// get end session endpoint
		String end_session_endpoint = getEndpointFromConfigOidc("end_session_endpoint",server_url);
		if( isEmpty(end_session_endpoint) ) {
            Logd(TAG,"logout : could not get end_session_endpoint on server : "+server_url);
			return false;
		}
		
        // set up connection
        HttpURLConnection huc = getHUC(end_session_endpoint);
        huc.setInstanceFollowRedirects(false);

        huc.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        
        huc.setDoOutput(true);
        huc.setChunkedStreamingMode(0);
        // prepare parameters
        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(1);

        try {
        	// write parameters to http connection
	        OutputStream os = huc.getOutputStream();
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
					os, "UTF-8"));
			// get URL encoded string from list of key value pairs
			String postParam = getQuery(nameValuePairs);
			Logd("Logout","url: "+end_session_endpoint);
			Logd("Logout","POST: "+postParam);
			writer.write(postParam);
			writer.flush();
			writer.close();
	        os.close();

	        // try to connect
	        huc.connect();
	        // connexion status
            int responseCode = huc.getResponseCode();
            Logd(TAG, "Logout response: "+responseCode);
            // if 200 - OK
            if ( responseCode == 200 ) {
                return true;
            }
            huc.disconnect();
        } catch ( Exception e) {
        	e.printStackTrace();
        	return false;
        }

        return false;
	}

	// return specified end point from server oidc configuration
	static String getEndpointFromConfigOidc(String endpoint, String server_url) {

		if( isEmpty(endpoint) || isEmpty(server_url) )
			return null;
		
		if( !server_url.endsWith("/") )
			server_url += "/";
		
		// retrieve openid-config
		JSONObject json = getHttpJSON(server_url+openIdConfigurationUrl);
		if( json == null ) {
            Logd(TAG,"getEndpointFromConfigOidc : could not get openid-configuration on server "+server_url);
			return null;
		}

		// get specified endpoint
		String server_endpoint = json.optString(endpoint);
		if( isEmpty(server_endpoint) ) {
            Logd(TAG,"getEndpointFromConfigOidc : could not get "+endpoint+" on server "+server_url);
			return null;
		}
		
		// return found value
		return server_endpoint;
	}
	
	// get JSON object from an URL
	static JSONObject getHttpJSON(String url) {
		JSONObject json = null;
		String s = getHttpString(url);
		if(s!=null) {
    		try {
    			json = new JSONObject(s);
    		} catch (Exception e) {}
		}
			
		return json;
	}
	
	// get a text resource from an URL
	static String getHttpString(String url) {

		String result = null;
		
		// build connection
        HttpURLConnection huc = getHUC(url);
        huc.setInstanceFollowRedirects(false);

        try {
	        // try to establish connection 
           huc.connect();
           // get result
           int responseCode = huc.getResponseCode();
           Logd(TAG, "getHttpString response: "+responseCode);
           
           // if 200, read http body
           if ( responseCode == 200 ) {
               InputStream is = huc.getInputStream();
               result= convertStreamToString(is);
               is.close();
           } else {
        	   // result = "response code: "+responseCode;
           }
           
           // close connection
           huc.disconnect();
	        
		} catch (Exception e) {
            Log.e(TAG, "revokeSite FAILED");
			e.printStackTrace();
		}
        
		return result;
	}

	// some logging functions
	// comment to disable trace
	static void sysout(String s) {
    	// if(s!=null) System.out.println(s);
    }
	static void Logd(String tag, String msg) {
		if(tag!=null && msg!=null) Log.d(tag, msg);
	}

}
