package com.orange.oidc.tim.hello;

import org.json.JSONObject;

import com.orange.oidc.tim.service.IRemoteListenerToken;
import com.orange.oidc.tim.service.IRemoteService;

import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.preference.PreferenceManager;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

// Main display
public class OIDCActivity extends Activity {

	protected static final String TAG = "oidc";

	// oidc server connection parameters
	String serverUrl     = null;
	String responseType  = "code id_token";
	String scope         = "openid";
	String state         = "af0ifjsldkj";
	String nonce         = "n-0S6_WzA2Mj";
	String redirect_uri  = "https://client.example.org/cb";;
	String client_id     = "s6BhdRkqt3";
	String client_secret = null;

	// returned results from service
	String m_code = null;
	String m_id_token = null;
	String m_access_token = null;
	String m_user_info = null;

	// service connection 
	RemoteServiceConnection connection;
	// remote service 
	IRemoteService service;

	/**
	 * This class represents the actual service connection. It casts the bound
	 * stub implementation of the service to the AIDL interface.
	 */
	class RemoteServiceConnection implements ServiceConnection {

		public void onServiceConnected(ComponentName name, IBinder boundService) {
			// connection established, get remote service object
			service = IRemoteService.Stub.asInterface(boundService);
			
			Log.d(TAG, "onServiceConnected() connected");
			toast("Service connected",1);
			
			loginBtn.setText("login");

			autoUserInfo();
		}

		public void onServiceDisconnected(ComponentName name) {
			// connection closed
			service = null;
			
			loginBtn.setText("connect");
			
			Log.d(TAG, "onServiceDisconnected() disconnected");
			toast("Service disconnected",1);
		}
	}

	// hide login and progress bar buttons
	private void hideButtons() {
		loginBtn.setVisibility(View.GONE);
		pb.setVisibility(View.GONE);
	}
	
	// Binds this activity to the service
	private boolean initService() {
		connection = new RemoteServiceConnection();
/*
        try {
    		connectionInternal = new RemoteServiceConnectionInternal();
        	bindService(new Intent(IRemoteServiceInternal.class.getName()),
                connectionInternal, Context.BIND_AUTO_CREATE);
        } catch (SecurityException se) {
        	toast("Security Error :\nnot allowed to connect to the service internal", 2);
        } catch (Exception e) {
        	e.printStackTrace();
        }
*/
        boolean bRet = false;
        try {
        	bRet = bindService(new Intent(IRemoteService.class.getName()),
                connection, Context.BIND_AUTO_CREATE);
        } catch (SecurityException se) {
        	toast("Security Error :\nnot allowed to connect to the service", 2);
        } catch (Exception e) {
        	e.printStackTrace();
        }

		Log.d(TAG, "initService() bound result: " + bRet);

        return bRet;
	}
	
	// Unbinds this activity from the service.
	private void releaseService() {
		if (connection != null) {
			unbindService(connection);
			connection = null;
			Log.d(TAG, "releaseService() unbound.");
		}
	}

	// ui objects
	Button loginBtn;

	TextView txtHello;
	WebView  webView;
	ProgressBar pb;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		// Setup the UI
		webView = (WebView) findViewById(R.id.webView);
		txtHello = (TextView) findViewById(R.id.textHello);
		pb = (ProgressBar) findViewById(R.id.progressBar);
		loginBtn = (Button) findViewById(R.id.login);

		hideButtons ();
		
		loadSettings();

		// connect to the service
		if( initService() == false ) {
			addToWebview("<font color=\"red\">Service not connected</font><br>");
		}

		// set action listener
		loginBtn.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				if (service == null) {
					// connect to the service if not connected
					initService();
				} else {
					// do the request
					doLogin();
				}
			}
		});
		
	}

	// load parameters from shared preferences
	void loadSettings() {
		SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this);

		serverUrl     = sharedPrefs.getString("server_url",    serverUrl);
		responseType  = sharedPrefs.getString("response_type", responseType);
		scope         = sharedPrefs.getString("scope",         scope);
		state         = sharedPrefs.getString("state",         state);
		nonce         = sharedPrefs.getString("nonce",         nonce);
		redirect_uri  = sharedPrefs.getString("redirect_uri",  redirect_uri);
		client_id     = sharedPrefs.getString("client_id",     client_id);
		client_secret = sharedPrefs.getString("client_secret", client_secret);
		
		m_access_token    = sharedPrefs.getString("access_token", null);
		Log.d(TAG,"loadSettings: m_access_token: "+m_access_token);
	}

	// show menu
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.oidc, menu);
		return true;
	}

	final int SETTINGS_RETURN_CODE = 152124;
	
	// menu events
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {

		if(item.getItemId() == R.id.action_settings) {
			startActivityForResult(new Intent(this, SettingsActivity.class),SETTINGS_RETURN_CODE);
			saveAccessToken();
		} if(item.getItemId() == R.id.action_clear_token) {
			clearTokens();
			html="";
			addToWebview("");
		} else if(item.getItemId() == R.id.action_TIM) {
			releaseService();
			startActivity(new Intent(this, MainActivity.class));
			finish();
		}

		return super.onOptionsItemSelected(item);
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		if (requestCode == SETTINGS_RETURN_CODE ) {
			loadSettings();
		}
	}
	
	/** Called when the activity is about to be destroyed. */
	@Override
	protected void onDestroy() {
		// clean up service on activity ending
		releaseService();
		super.onDestroy();
	}

	// clear all tokens and empty display
	void clearTokens() {
		// clear local saved tokens
		m_code = null;
		m_id_token = null;
		m_user_info = null;
		m_access_token = null;
		saveAccessToken();
		// clear visual output
		loginBtn.setVisibility(View.VISIBLE);
		pb.setVisibility(View.GONE);
		txtHello.setText("");
		// and logout from server
		new Thread() {
			@Override
			public void run() {
				try {
					if( service!=null ) {
						service.logout(serverUrl);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}.start();
	}
	

	// retrieve user info in automatic mode
	// show login button if token expired or can not get a new one
	void autoUserInfo() {
		new Thread() {
			@Override
			public void run() {
				if(m_access_token!=null && service!=null) {
					getUserInfo();
					return;
				}
				
				// update ui with result
				runOnUiThread(new Runnable() {
					@Override
					public void run() {
							loginBtn.setVisibility(View.VISIBLE);
					}
				});
			}
		}.start();
	}
	
	// request tokens to the service
	void doLogin() {
		Log.d(TAG, "doLogin");
		
		// show progress bar animation
		pb.setVisibility(View.VISIBLE);

		// toast("asking new tokens", 1);
		addToWebview("asking new tokens");
		
		// do in a different thread to not block UI
		new Thread() {
			@Override
			public void run() {
				try {
					// serviceInternal.resetCookies();

					// call the remote service with specified parameters
					if (service != null) {
						Log.d(TAG, "doLogin : launch get tokens");
						service.getTokens(
								remoteListenerToken,
								serverUrl,
								client_id,
								client_secret,
								scope,
								redirect_uri,
								state,
								nonce);
						Log.d(TAG, "doLogin : waiting tokens");
					}
				} catch (final Exception e) {
					Log.d(TAG, "doLogin failed with: " + e);
					e.printStackTrace();
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							// show progress bar animation
							pb.setVisibility(View.GONE);
							addToWebview("<font color=\"red\">"+e.getMessage()+"</font>");
						}});
				}
			}
		}.start();
	}

	// save tim_access_token value to shared preferences
	void saveAccessToken() {
		SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this);
		Editor editor = sharedPrefs.edit();
		editor.putString("access_token", m_access_token);
		editor.commit();
	}
	
	// request user info
	void getUserInfo() {
		// show progress bar animation
		// update ui with result
		runOnUiThread(new Runnable() {

			@Override
			public void run() {
				pb.setVisibility(View.VISIBLE);
			}
		});

		// do in a different thread to not block UI
		new Thread() {
			@Override
			public void run() {
				try {
					if (service != null) {
						Token tk = new Token();
						tk.fromToken(m_access_token);
						Log.d(TAG,"Token expiration: "+tk.exp);
						Log.d(TAG,"Token date: "+Token.fromCal(tk.getExp()));
						// call the remote service with specified parameters
						m_user_info = service.getUserInfo(serverUrl, m_access_token);
						Log.d("user_info",""+m_user_info);
						if(m_user_info==null) {
							runOnUiThread(new Runnable() {
								@Override
								public void run() {
									addToWebview("<font color=\"red\">User info failed</font>");
								}
							});
							// token is invalid
							m_access_token = "";
							saveAccessToken();
						}
		
						// update ui with result
						runOnUiThread(new Runnable() {
		
							@Override
							public void run() {
								hideButtons();
								if(m_user_info!=null) {
									UserInfo ui = new UserInfo(m_user_info);
									txtHello.setText("Hello " + ui.get("name") + " ("+ui.get("email") + ")");
									addToWebview("<font color=\"green\">User info OK</font>");
								} else {
									loginBtn.setVisibility(View.VISIBLE);
								}
							}
						});
					}
				} catch (RemoteException e) {
					Log.d(TAG, "doLogin failed with: " + e);
					e.printStackTrace();
				}
			}
		}.start();
	}

	// token response callback from service
	private IRemoteListenerToken.Stub remoteListenerToken = new IRemoteListenerToken.Stub() {

		@Override
		public void handleTokenResponseWithTim(
				String id_token,
				String tim_access_token,
				boolean user_cancel
				 )
				throws RemoteException {
			// do nothing ...
		}

		@Override
		public void handleTokenResponse( String tokens )
				throws RemoteException {
			
			Log.d(TAG,"handleTokenResponse "+tokens);
			
			try {
	        	JSONObject jObject = new JSONObject(tokens);

	        	boolean user_cancel = false;
	        	String userCancel   = getFromJS( jObject, "cancel" );
	        	if(userCancel!=null && userCancel.equalsIgnoreCase("true") ) {
	        		user_cancel = true;
	        	}

	        	if( user_cancel ) {
					// get user info
					runOnUiThread(new Runnable() {
		
						@Override
						public void run() {
							if( m_id_token == null || m_id_token.length() == 0) {
								addToWebview("<font color=\"orange\">user cancel</font>");
								pb.setVisibility(View.GONE);
							}
						}
					});
					return;
					
				}

	        	m_access_token  = getFromJS( jObject, "access_token" );
	        	// String token_type    = getFromJS( jObject, "token_type" );
	        	String refresh_token  = getFromJS( jObject, "refresh_token" );
	        	String expires_in     = getFromJS( jObject, "expires_in" );
	        	m_id_token       = getFromJS( jObject, "id_token" );
				saveAccessToken();
				
				// check refresh_token
				Log.d(TAG,"refresh_token "+refresh_token);
				if(refresh_token!=null && refresh_token.length()>0) {
					refreshToken(refresh_token);
				}
				
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
			
			if( m_access_token!=null && m_access_token.length()>0 )
				autoUserInfo();
			else {
				// get user info
				runOnUiThread(new Runnable() {
	
					@Override
					public void run() {
						if( m_id_token == null || m_id_token.length() == 0) {
							addToWebview("<font color=\"red\">authentication failed</font>");
							pb.setVisibility(View.GONE);
						} else if( m_access_token == null || m_access_token.length() == 0) {
							addToWebview("<font color=\"red\">error access token</font>");
							pb.setVisibility(View.GONE);
						}
					}
				});
			}
		}
	};
	
	void refreshToken(final String refresh_token) {
		// do in a different thread to not block UI
		new Thread() {
			@Override
			public void run() {
				try {
					if(service!=null) {
						String refresh = service.refreshToken(serverUrl, client_id, client_secret, scope, redirect_uri, refresh_token);
						Log.d(TAG,"service.refresh_token: "+refresh);
						try {
				        	JSONObject jObject = new JSONObject(refresh);
				        	m_access_token  = getFromJS( jObject, "access_token" );
							saveAccessToken();
				        } catch (Exception e) {
				            e.printStackTrace();
				        }
					}
				} catch (RemoteException e) {
					Log.d(TAG, "doLogin failed with: " + e);
					e.printStackTrace();
				}
			}
		}.start();
	}
	
	// display toast to screen
	void toast(String msg, int duration) {
		android.widget.Toast.makeText(
				OIDCActivity.this,
				msg,
				duration == 0 ? android.widget.Toast.LENGTH_SHORT : android.widget.Toast.LENGTH_LONG ).show();
	}

	// display event history in webview
	String html="";
	void addToWebview(String msg) {
		html += msg + "<br>";
        webView.loadData(html, "text/html", "UTF8");
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

}
