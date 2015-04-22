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

import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import org.json.JSONException;
import org.json.JSONObject;

import org.simalliance.openmobileapi.*;

import com.orange.oidc.tim.service.IRemoteListenerToken;
import com.orange.oidc.tim.service.IRemoteService;
import com.orange.oidc.tim.service.IRemoteServiceInternal;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;


/**
 * Openid Connect proxy service class
 *
 */
public class Service extends android.app.Service implements SEService.CallBack {

	protected static final String TAG = "Service";
	
	final static String EMPTY = "";
	
	static {
	    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	int idList=0;
	class RemoteListenerToken {
		IRemoteListenerToken listener;
		String id;
		boolean useTim;
		OpenidConnectParams ocp;
		RemoteListenerToken(IRemoteListenerToken r) {
			listener = r;
			idList++;
			id = ""+idList;
		}
	};
	
	List <RemoteListenerToken> RemoteListenerTokenList = new ArrayList<RemoteListenerToken>();
	
	public static Service theService = null;
	
	private static TimSecureStorage secureStorage;
	
	public Service() {
		// android.os.Debug.waitForDebugger();
		System.setProperty("http.keepAlive", "false");
		if( theService == null ) {
			theService = this;
			// init secure storage
			secureStorage = new SDCardStorage();
			// secureStorage = new SIMStorage();
			
			// init Http
			HttpOpenidConnect.secureStorage = secureStorage;
		}
	}

	// private final IRemoteServiceBinder mBinder = new IRemoteServiceBinder();

	public class ServiceBinder extends Binder {
		Service getService() {
			return Service.this;
		}
	}

	private final IRemoteService.Stub mBinder = new IRemoteService.Stub() {
		
		@Override
		public void getTokensWithTim(
		        IRemoteListenerToken listener,
		        String serverUrl,
		        String client_id,
				String scope,
				String state,
		        String nonce )
				throws RemoteException {

			Logd(TAG,"getTokensWithTim begin");

			showNotProtectedNotifIcon();
			
			if(!serverUrl.endsWith("/")) serverUrl += "/";
			
			scope = sortScope(scope+" tim");
			
	        OpenidConnectParams ocp = new OpenidConnectParams(serverUrl, client_id, scope, secureStorage.getRedirectUri(), state, nonce, null, null, null);

			Logd(TAG,"ocp: "+ocp.toString());
	        
	        RemoteListenerToken rl;
			synchronized(RemoteListenerTokenList) {
				rl = new RemoteListenerToken(listener);
				rl.ocp = ocp;
				rl.useTim = true;
				RemoteListenerTokenList.add(rl);
			}

			// check if tokens present
			try {
	
				TokensKeys tk = null;
				if(secureStorage!=null)
					tk = secureStorage.read_tokens(serverUrl, client_id, scope+" tim");

				if(tk!=null) {
					// check validity of refresh token
                    Log.d(TAG,"refresh token found, validity check begin");
                    Log.d(TAG,"expiration du token : "+tk.getExpires());
					if(tk.isRefreshTokenValid()) {
						// refresh token keys
						Logd(TAG,"getTokensWithTim refreshTokenWithTim");
						String refreshResult = refreshTokenWithTim(serverUrl, client_id, scope);
						Logd(TAG,"getTokensWithTim refresh result: ");
						Logd(TAG,""+refreshResult);
						setClientTokens(rl.id,refreshResult);
						Logd(TAG,"getTokensWithTim refreshTokenWithTim end");
						return;
					}
				} else if ( tk == null ) {
					// for test only
					// return;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			// every tokens expired, make a new request
	        HttpOpenidConnect hc = new HttpOpenidConnect(ocp);

			if( ! hc.getTokens( Service.this, rl.id, true, null )  ) {
				setClientTokens(rl.id,null);
			}

			Logd(TAG,"getTokensWithTim end");

		}

		@Override
		public String getTimUserInfo(String serverUrl, String tim_access_token)
				throws RemoteException {
			Logd(TAG,"getTimUserInfo");
			showProtectedNotifIcon();
			String result = HttpOpenidConnect.getTimUserInfo(serverUrl, tim_access_token);
			// hideNotifIcon();
			return result;
		}

		@Override
	    public String refreshTokenWithTim(
	            String serverUrl,
	            String client_id,
	            String scope
	            ) {
			Logd(TAG,"refreshTokenWithTim");

			showNotProtectedNotifIcon();

			scope = sortScope(scope+" tim");

			if(!serverUrl.endsWith("/")) serverUrl += "/";
			OpenidConnectParams ocp = new OpenidConnectParams(
					    				serverUrl, 
					    				client_id, 
					    				scope, 
					    				secureStorage.getRedirectUri() );
    		HttpOpenidConnect hc = new HttpOpenidConnect( ocp );

			try {
				String response = hc.refreshTokenWithTIM();
				Logd(TAG,"refreshTokenWithTim response: "+response);
				if(response!=null) {
					JSONObject json = new JSONObject(response);
					String id_token      = getFromJS( json,"id_token");
					String refresh_token = getFromJS( json, "refresh_token");
					ocp.m_server_scope   = getFromJS( json, "scope");

					JSONObject retJSon = new JSONObject();
					retJSon.put("id_token", id_token);

					String expires = TimSecureStorage.convertExpiresIn( getFromJS(json, "expires_in") );
					// save new tokens
					secureStorage.update_tokens(ocp, id_token, refresh_token, expires );
					retJSon.put("tim_access_token", secureStorage.getNewTimToken(ocp));

					// hideNotifIcon();
					return retJSon.toString();
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
			// hideNotifIcon();
			return null;
		}

		@Override
	    public String getNewTimToken(
	            String serverUrl,
	            String client_id,
	            String scope
	            ) {
			Logd(TAG,"getNewTimToken");
			showProtectedNotifIcon();

			scope = sortScope(scope+" tim");

			if(!serverUrl.endsWith("/")) serverUrl += "/";
			
			OpenidConnectParams ocp = new OpenidConnectParams(serverUrl, client_id, scope, null);
			
			String newTimToken = secureStorage.getNewTimToken(ocp);

			// hideNotifIcon();
			
			return newTimToken;
		}

	    @Override
	    public boolean deleteTokens(
	            String serverUrl,
	            String client_id,
	            String scope
	            ) {
			Logd(TAG,"deleteTokens "+client_id);

			resetCookies();

            scope = sortScope(scope);
			if(!serverUrl.endsWith("/")) serverUrl += "/";

			return secureStorage.delete_tokens(serverUrl, client_id, scope);
	    }

	    @Override
	    public String webFinger(
	            String userInput,
	            String serverUrl
	            ) {
			try {
				return HttpOpenidConnect.webfinger(userInput, serverUrl);
			} catch (Exception e) {
				
			}
			return null;
		}

	    /** openid connect only methods
	     */
		@Override
		public void getTokens(
	        IRemoteListenerToken listener,
	        String serverUrl,
	        String client_id,
	        String client_secret,
	        String scope, 
	        String redirect_uri, 
	        String state, 
	        String nonce ) {
			
			Logd(TAG,"getTokens begin");
			
			scope = sortScope(scope);
			if(!serverUrl.endsWith("/")) serverUrl += "/";
			
	        OpenidConnectParams ocp = new OpenidConnectParams();
	        ocp.init(serverUrl, client_id, scope, redirect_uri, state, nonce, null, client_secret, null);

	        RemoteListenerToken rl;
			synchronized(RemoteListenerTokenList) {
				rl = new RemoteListenerToken(listener);
				rl.ocp = ocp;
				RemoteListenerTokenList.add(rl);
			}

	        HttpOpenidConnect hc = new HttpOpenidConnect(ocp);

			if( ! hc.getTokens( Service.this, rl.id, false, null ) ) {
				setClientTokens(rl.id,null);
			}

			Logd(TAG,"getTokens end");
		}
	
		@Override
		public String refreshToken(
	        String serverUrl,
	        String client_id,
	        String client_secret,
	        String scope, 
	        String redirect_uri,
	        String refresh_token
	        ) {

			scope = sortScope(scope);
			if(!serverUrl.endsWith("/")) serverUrl += "/";
			OpenidConnectParams ocp = new OpenidConnectParams(
					    				serverUrl, 
					    				client_id, 
					    				scope, 
					    				redirect_uri );
    		HttpOpenidConnect hc = new HttpOpenidConnect( ocp );

			try {
				String response = hc.refreshToken(refresh_token);
				Logd(TAG,"refreshToken response: "+response);
				if(response!=null) {
					return response;
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
			return null;
		}
 
		@Override
		public String getUserInfo(
			String serverUrl,
			String access_token ) {
			return HttpOpenidConnect.getUserInfo(serverUrl, access_token);
		}

		// Logout from the idp
		@Override
	    public void logout(String serverUrl) {
			HttpOpenidConnect.logout(serverUrl, null);
		}

		/*
		 * (non-Javadoc)
		 * @see com.orange.openid_connect_php.IRemoteService#logout(java.lang.String)
		 * Logout from TIM, IdP and Cloud service
		 */
		@Override
		public void revokeLogoutWithTim(
		        String serverUrl,
		        String client_id,
		        String scope ) {

	        // android.os.Debug.waitForDebugger();

			if(!serverUrl.endsWith("/")) serverUrl += "/";
			scope = sortScope(scope+" tim");;

			// search for TokenKey
			TokensKeys tk = secureStorage.read_tokens(serverUrl, client_id, scope);
			if ( tk==null || tk.jwkPub == null || tk.jwkPub.length() == 0 ) {
				// bad parameter, no tim app key found
				return;
			}
			
			// build custom tim access token with tim app key
			OpenidConnectParams ocp = new OpenidConnectParams(
    				serverUrl, 
    				client_id, 
    				scope, 
    				null );
			ocp.m_jwk = tk.jwkPub;
			
			if (HttpOpenidConnect.logout(serverUrl,secureStorage.getNewTimToken(ocp))) {
				Logd(TAG,"Online deletion OK");
			}
				
			Logd(TAG,"Deleting local information");
			secureStorage.delete_tokens(serverUrl, client_id, scope);
			resetCookies();
		}

	};

	void resetCookies() {
    	// init intent
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClass(Service.this, WebViewActivity.class);

        intent.putExtra("resetcookies", "true" );
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_NO_ANIMATION);

        // launch webview
        startActivity(intent);
	}
	
	long getSecretPathThreshold() {
		SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this);
		long l= sharedPrefs.getLong("threshold", 80);
		return l;
	}
	
	void setSecretPathThreshold(long val) {
		SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this);
		Editor editor = sharedPrefs.edit();
		editor.putLong("threshold", val);
		editor.commit();
		Logd(TAG,"threshold: "+val);
	}
	
	// internal remote service for internal webview
	private final IRemoteServiceInternal.Stub mBinderInternal = new IRemoteServiceInternal.Stub() {

		private void setTokensRedirect(String id, HttpOpenidConnect hc, String redirect) {
			// android.os.Debug.waitForDebugger();

			// check caller uid
			if( checkCallingUid() == false ) {
				// caller are not from inside this app
				Logd(TAG,"setTokensRedirect not from inside this app");
				return;
			}

			RemoteListenerToken rl=null;
			synchronized(RemoteListenerTokenList) {
				for(int i=RemoteListenerTokenList.size()-1; i>=0; i--) {
					RemoteListenerToken r = RemoteListenerTokenList.get(i);
					if(r.id.compareTo(id)==0) {
						rl = r;
						RemoteListenerTokenList.remove(i);
						break;
					}
				}
			}
			
			if( rl != null  ) {
		        try {
		        	String tokens = hc.doRedirect(redirect,rl.useTim);

		        	if(rl.useTim) {
			        	JSONObject jObject = new JSONObject(tokens);

			        	boolean user_cancel = false;
			        	String userCancel   = getFromJS( jObject, "cancel" );
			        	if(userCancel!=null && userCancel.equalsIgnoreCase("true") ) {
			        		user_cancel = true;
			        	}
			        	
			        	// put id_token and refresh_token in Secure Storage
			        	if(user_cancel==false) {
				        	// String access_token  = getFromJS( jObject, "access_token" );
				        	// String token_type    = getFromJS( jObject, "token_type" );
				        	String refresh_token = getFromJS( jObject, "refresh_token" );
				        	String expires_in    = getFromJS( jObject, "expires_in" );
				        	String id_token      = getFromJS( jObject, "id_token" );
				        	rl.ocp.m_server_scope= getFromJS( jObject, "scope" );
	
	
				        	secureStorage.save_tokens(rl.ocp,id_token,refresh_token,expires_in);
							
				        	// HACK : not nice ... :(
				        	hc.mOcp.m_redirect_uri = null;

							// do now the refresh
							String refreshResult = hc.refreshTokenWithTIM();
							if ( refreshResult != null ) {
								if(refreshResult!=null) {
									JSONObject json = new JSONObject(refreshResult);
									id_token              = getFromJS( json,"id_token");
									refresh_token         = getFromJS( json, "refresh_token");
									rl.ocp.m_server_scope = getFromJS( json, "scope");
	
						        	String tim_token = null;
						        	if(secureStorage!=null) {
										String expires = TimSecureStorage.convertExpiresIn( getFromJS(json, "expires_in") );
										// save new tokens
										secureStorage.update_tokens(hc.mOcp, id_token, refresh_token, expires);
										tim_token = secureStorage.getNewTimToken(hc.mOcp);
						        	}
					        		rl.listener.handleTokenResponseWithTim(id_token, tim_token, false );
									return;
								}
							}
			        	} else {
			        		rl.listener.handleTokenResponseWithTim(EMPTY, EMPTY, true );
			        		return;
			        	}

		        	} else {
		        		rl.listener.handleTokenResponse(tokens);
		        		return;
		        	}
		        	
		        } catch (Exception e) {
		            e.printStackTrace();
		        }
		        
		        // if here, then nothing to notify
				if( rl.listener!=null ) {
					try {
			        	if(rl.useTim)
			        		rl.listener.handleTokenResponseWithTim(EMPTY, EMPTY, false );
			        	else
			        		rl.listener.handleTokenResponse(EMPTY);
					} catch (RemoteException e) {
						e.printStackTrace();
					}
				}
			}

		}
		
		@Override
		public void setTokens(String id, String tokens) throws RemoteException {
			
			// check caller uid
			if( checkCallingUid() == false ) {
				// caller are not from inside this app
				Logd(TAG,"setTokens not from inside this app");
				return;
			}

			RemoteListenerToken rl=null;
			synchronized(RemoteListenerTokenList) {
				for(int i=RemoteListenerTokenList.size()-1; i>=0; i--) {
					RemoteListenerToken r = RemoteListenerTokenList.get(i);
					if(r.id.compareTo(id)==0) {
						rl = r;
						RemoteListenerTokenList.remove(i);
						break;
					}
				}
			}
			
			if( rl != null  ) {

	        	JSONObject jObject = null;
		        try {
		        	if(tokens!=null)
		        		jObject = new JSONObject(tokens);

		        	// String access_token   = getFromJS( jObject, "access_token" );
		        	// String token_type    = getFromJS( jObject, "token_type" );
		        	String refresh_token  = getFromJS( jObject, "refresh_token" );
		        	String expires_in     = getFromJS( jObject, "expires_in" );
		        	String id_token       = getFromJS( jObject, "id_token" );
		        	rl.ocp.m_server_scope = getFromJS( jObject, "scope" );
		        	boolean user_cancel = false;
		        	String userCancel   = getFromJS( jObject, "cancel" );
		        	if(userCancel!=null && userCancel.equalsIgnoreCase("true") ) {
		        		user_cancel = true;
		        	}
		        	
		        	// put id_token and refresh_token in Secure Storage
		        	if ( rl.useTim ) {
			        	String tim_token = null;
			        	if(user_cancel==false) {
			        		secureStorage.save_tokens(rl.ocp,id_token,refresh_token,expires_in);
							tim_token = secureStorage.getNewTimToken(rl.ocp);
			        	}
		        	
		        		rl.listener.handleTokenResponseWithTim(id_token, tim_token, false );
		        	} else {
		        		rl.listener.handleTokenResponse( tokens );
		        	}
					
					// hideNotifIcon();
					return;
		        } catch (JSONException e) {
		            e.printStackTrace();
		        }
			}
			
			if(rl!=null && rl.listener!=null ) {
	        	if(rl.useTim)
	        		rl.listener.handleTokenResponseWithTim(EMPTY, EMPTY, false );
	        	else
	        		rl.listener.handleTokenResponse( EMPTY );
			}

			// hideNotifIcon();
		}

		@Override
		public void doRedirect( String id, String redirect ) {
			
			// check caller uid
			if( checkCallingUid() == false ) {
				// caller are not from inside this app
				Logd(TAG,"doRedirect not from inside this app");
				return;
			}

			Logd(TAG,"doRedirect begin");
			
			if(id==null || id.length()==0 ) {
				Logd(TAG,"doRedirect end no ID");
				// hideNotifIcon();
				return;
			}
			
	        OpenidConnectParams ocp = null;
			// android.os.Debug.waitForDebugger();
			
			synchronized(RemoteListenerTokenList) {
				for(int i=RemoteListenerTokenList.size()-1; i>=0; i--) {
					RemoteListenerToken r = RemoteListenerTokenList.get(i);
					if(r.id.compareTo(id)==0) {
				        ocp = new OpenidConnectParams(r.ocp);
						break;
					}
				}
			}

			if( ocp != null ) {
		        HttpOpenidConnect hc = new HttpOpenidConnect(ocp);

		        try { 
		        	setTokensRedirect(id, hc, redirect );
		        	return;
		        } catch(Exception e) {
		        	e.printStackTrace();
		        }
			}
			
			// if error, set null response
	        try { 
	        	setTokens(id, null );
	        } catch(Exception e) {
	        	e.printStackTrace();
	        }

	        Logd(TAG,"doRedirect end");
			// hideNotifIcon();
		}

		@Override
		public void resetCookies() throws RemoteException {
			
			// check caller uid
			if( checkCallingUid() == false ) {
				// caller are not from inside this app
				Logd(TAG,"resetCookies not from inside this app");
				return;
			}

			// clear cookies
	        // android.webkit.CookieManager.getInstance().removeAllCookie();
		}

		// check calling process uid, if different return false
		// possibility of hack
		private boolean checkCallingUid() {
			// check uid
			if( android.os.Process.myUid() == Binder.getCallingUid() ) {
				return true;
			}
			
			// uid are not the same
			return false;
		}

	};

	@Override
	public void onCreate() {
		super.onCreate();
	}

	// disconnect from SIM card service on service termination
	@Override
	public void onDestroy() {
		hideNotifIcon();
		disconnectSEService();
		super.onDestroy();
	}
	
	// service starting
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
        return Service.START_NOT_STICKY;
	}

	// new connection to service, connect SIM card service if not connected
    @Override
    public IBinder onBind(Intent intent) {
        // Select the interface to return.  If your service only implements
        // a single interface, you can just return it here without checking
        // the Intent.
        if (IRemoteService.class.getName().equals(intent.getAction())) {
    		showProtectedNotifIcon();
    		Logd(TAG,"onBind Service");
    		connectSEService();
            return mBinder;
        }
        if (IRemoteServiceInternal.class.getName().equals(intent.getAction())) {
    		Logd(TAG,"onBind ServiceInternal");
    		connectSEService();
            return mBinderInternal;
        }
        return null;
    }

    // connect to SIM card service
	public void connectSEService() {
		// check if not already connected
		if( SIMStorage.seService != null ) {
			if( SIMStorage.seService.isConnected() )
				return;
		}

		// instantiate SEService object
		try {
			Logd(TAG, "creating SEService object");
			SIMStorage.seService = new SEService(this, this);
		} catch (SecurityException e) {
			Log.e(TAG,
					"Binding not allowed, uses-permission org.simalliance.openmobileapi.SMARTCARD?");
		} catch (Exception e) {
			Log.e(TAG, "connectSEService exception: " + e.getMessage());
		}
	}

	// disconnect from SIM card service
	public void disconnectSEService() {
		if (SIMStorage.seService != null && SIMStorage.seService.isConnected()) {
			SIMStorage.seService.shutdown();
		}
	}

	// SIM card service connection notification
	public void serviceConnected(SEService service) {
		// Log.i(LOG_TAG, "seviceConnected()");
		Toast.makeText(this, "SIM CARD SERVICE CONNECTED", Toast.LENGTH_SHORT).show();
	}

	void setClientTokens(String id, String tokens) {
		Logd(TAG,"setClientTokens id:"+id);
		Logd(TAG,"setClientTokens tokens:"+tokens);
		RemoteListenerToken rl=null;
		synchronized(RemoteListenerTokenList) {
			for(int i=RemoteListenerTokenList.size()-1; i>=0; i--) {
				RemoteListenerToken r = RemoteListenerTokenList.get(i);
				if(r.id.compareTo(id)==0) {
					rl = r;
					RemoteListenerTokenList.remove(i);
					break;
				}
			}
		}
		
		if( rl != null  ) {

        	JSONObject jObject = null;
	        try {
	        	if(tokens!=null)
	        		jObject = new JSONObject(tokens);

	        	if(jObject!=null) {
		        	// String access_token  = getFromJS( jObject, "access_token" );
		        	// String token_type    = getFromJS( jObject, "token_type" );
		        	String refresh_token  = getFromJS( jObject, "refresh_token" );
		        	String expires_in     = getFromJS( jObject, "expires_in" );
		        	String id_token       = getFromJS( jObject, "id_token" );
		        	rl.ocp.m_server_scope = getFromJS( jObject, "scope" );
		        	boolean user_cancel = false;
		        	String userCancel   = getFromJS( jObject, "cancel" );
		        	if(userCancel!=null && userCancel.equalsIgnoreCase("true") ) {
		        		user_cancel = true;
		        	}
		        	
					// android.os.Debug.waitForDebugger();
		        	
		        	if(rl.useTim) {
			        	// put id_token and refresh_token in Storage ( SIM or SDCard )
			        	secureStorage.save_tokens(rl.ocp,id_token,refresh_token,expires_in);
			        	String tim_token = secureStorage.getNewTimToken(rl.ocp);
			        	
						rl.listener.handleTokenResponseWithTim( id_token, tim_token, user_cancel );
		        	} else {
		        		
		        	}
	
					return;
	        	}
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
		}
		
		if(rl!=null && rl.listener!=null ) {
			try {
	        	if(rl.useTim)
	        		rl.listener.handleTokenResponseWithTim(EMPTY, EMPTY, false );
	        	else
	        		rl.listener.handleTokenResponse( EMPTY );
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
		}
		
	}
	
	
	// get a string from a json object
	String getFromJS(JSONObject jo, String name){
		if ( jo != null ) {
			try {
				return jo.getString(name);
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	String sortScope(String scope) {
		// sort scope in alphabetical order
		if( scope != null ) {
    		scope = scope.toLowerCase(Locale.getDefault());
    		// offline_access is mandatory
    		if ( !scope.contains("offline_access") ) {
    			scope += " offline_access";
    		}
    		/*
    		// and tim too for php oidc
    		if ( !scope.contains("tim") ) {
    			scope += " tim";
    		}
    		*/
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
		return scope;
	}
	
	void toast(final String msg, final int duration) {
		new android.os.Handler(android.os.Looper.getMainLooper())
				.post(new Runnable() {
					@Override
					public void run() {
						android.widget.Toast
								.makeText(
										theService,
										msg,
										duration == 0 ? android.widget.Toast.LENGTH_SHORT
												: android.widget.Toast.LENGTH_LONG)
								.show();
					}
				});
	}
	
	
	private void showProtectedNotifIcon() {
		showNotification(true);
	}

	private void showNotProtectedNotifIcon() {
		showNotification(false);
	}
	
	private void showNotification(boolean bProtect){
		Logd(TAG,"show protected icon "+bProtect);

        // this is it, we'll build the notification!
        // in the addAction method, if you don't want any icon, just set the first param to 0
        Notification mNotification = null;
        
        if(bProtect) {
        	mNotification = new Notification.Builder(this)

            .setContentTitle("TIM")
            .setContentText("privacy protected")
            .setSmallIcon(R.drawable.masked_on)
            .setAutoCancel(false)
            .build();
        } else {
        	mNotification = new Notification.Builder(this)

            .setContentTitle("TIM")
            .setContentText("privacy not protected")
            .setSmallIcon(R.drawable.masked_off)
            .setAutoCancel(false)
            .build();
        }

        // to make it non clearable
        mNotification.flags |= Notification.FLAG_NO_CLEAR;
        
        NotificationManager notificationManager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);

        // If you want to hide the notification after it was selected, do the code below
        // myNotification.flags |= Notification.FLAG_AUTO_CANCEL;

        notificationManager.notify(0, mNotification);
    }

    private void hideNotifIcon() {
		Logd(TAG,"hideNotifIcon");

        if (Context.NOTIFICATION_SERVICE!=null) {
            String ns = Context.NOTIFICATION_SERVICE;
            NotificationManager nMgr = (NotificationManager) getApplicationContext().getSystemService(ns);
            nMgr.cancel(0);
        }
    }

    void Logd(String tag, String msg) {
		if(tag!=null && msg!=null) Log.d(tag, msg);
	}

}
