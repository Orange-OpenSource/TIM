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

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;
import android.view.View;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;

import com.orange.oidc.tim.service.IRemoteServiceInternal;

public class WebViewActivity extends Activity {
	protected static final String TAG = "WebViewActivity";

	public WebView mWebView;

	String id;
	String login;
	String m_redirect_uri;
	
	boolean shouldFinish = false;	
	IRemoteServiceInternal remoteSI;
	RemoteServiceConnection connection;

	/**
	 * This class represents the actual service connection. It casts the bound
	 * stub implementation of the service to the AIDL interface.
	 */
	class RemoteServiceConnection implements ServiceConnection {

		public void onServiceConnected(ComponentName name, IBinder boundService) {
			remoteSI = IRemoteServiceInternal.Stub.asInterface((IBinder) boundService);

			Logd(TAG, "onServiceConnected() connected");
			if( shouldFinish ) {
				cancelAction();
			}
		}

		public void onServiceDisconnected(ComponentName name) {
			remoteSI = null;
			Logd(TAG, "onServiceDisconnected() disconnected");
		}
	}

	/** Binds this activity to the service. */
	private void initService() {
		connection = new RemoteServiceConnection();
		boolean ret = bindService(new Intent(IRemoteServiceInternal.class.getName()),
                connection, Context.BIND_AUTO_CREATE);
		Logd(TAG, "initService() bound with " + ret);
	}

	/** Unbinds this activity from the service. */
	private void releaseService() {
		remoteSI = null;
		if (connection != null) {
			unbindService(connection);
			connection = null;
			Logd(TAG, "releaseService() unbound.");
		}
	}
	  
	/** cancel the authentication action */
	private void cancelAction() {
        	if( remoteSI != null ) {
        		Handler handler = new Handler();
        		handler.postDelayed(new Runnable() {

        		    public void run() {
        		        try {
	                        Logd(TAG, "sending back result, callback id: "+id);
	                        remoteSI.setTokens(id,"{\"cancel\":\"true\"}");
        				} catch (Exception e) {
        					e.printStackTrace();
        				}
                		finish();
        		    }

        		}, 1000); // 5000ms delay        		
        	}
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
        // android.os.Debug.waitForDebugger();

		// connect to the service
	    initService();

        if (Integer.valueOf(android.os.Build.VERSION.SDK_INT) >= 9) {
            try {
                // StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX);
                Class<?> strictModeClass = Class.forName("android.os.StrictMode", true, Thread.currentThread()
                        .getContextClassLoader());
                Class<?> threadPolicyClass = Class.forName("android.os.StrictMode$ThreadPolicy", true, Thread.currentThread()
                        .getContextClassLoader());
                Field laxField = threadPolicyClass.getField("LAX");
                Method setThreadPolicyMethod = strictModeClass.getMethod("setThreadPolicy", threadPolicyClass);
                setThreadPolicyMethod.invoke(strictModeClass, laxField.get(null));
            }
            catch (Exception e) { }
        }

        // initialization of cookie manager
        android.webkit.CookieSyncManager.createInstance(this);
        android.webkit.CookieSyncManager.getInstance().startSync();
        // unrelated, just make sure cookies are generally allowed
        android.webkit.CookieManager.getInstance().setAcceptCookie(true);

        // magic starts here
        WebkitCookieManagerProxy coreCookieManager = new WebkitCookieManagerProxy(null, java.net.CookiePolicy.ACCEPT_ALL);
        java.net.CookieHandler.setDefault(coreCookieManager);

		Logd(TAG, "oncreate");
		
		// build webview
		mWebView = new WebView(this);
	    LinearLayout.LayoutParams lp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
		LinearLayout layout = new LinearLayout(this);
		layout.setBackgroundColor(0x00FFFFFF);

		layout.addView(mWebView,lp);
		setContentView(layout,lp);

		// configure webview
		mWebView.setVisibility(View.GONE);
		mWebView.setWebViewClient(new WebClient());
        mWebView.getSettings().setJavaScriptEnabled(true);
        mWebView.clearHistory();
        mWebView.clearFormData();
        mWebView.clearCache(true);

        // get parameters from intent
		Intent intent  = getIntent();
		String resetCookies = intent.getStringExtra("resetcookies");
		if(resetCookies!=null && resetCookies.length()>0) {
			coreCookieManager.resetCookies();
			finish();
			Logd(TAG,"reset : cookies cleared");
			return;
		}

		id = intent.getStringExtra("id");
		Logd(TAG,"ID callback: "+id);

		try {
			// get webview loading parameters
			String postParams = intent.getStringExtra("postParams");
			String server_url = intent.getStringExtra("server_url");
			m_redirect_uri    = intent.getStringExtra("redirect_uri");
			login = intent.getStringExtra("login");
			
			Logd(TAG,"webview post url: "+server_url);
			Logd(TAG,"webview post params: "+postParams);

			// connect to server
			mWebView.postUrl(server_url, postParams.getBytes());
			
		} catch (Exception e) {
			// end activity in case of error
			e.printStackTrace();
			shouldFinish = true;
		}
    }
	
    // web client to control webview url loading
    private class WebClient extends WebViewClient {
    	
    	@Override
    	public void onPageFinished(WebView view, String url) {

    		super.onPageFinished(view, url);
        	Logd(TAG,"webview onPageFinished: "+url);

        	if( mWebView.getContentHeight() == 0 ) {
        		// cancelAction(); return;
        	}
    		if(view.getVisibility()!=View.VISIBLE) {
    			view.setVisibility(View.VISIBLE);
    		}
    		
    		// just a little hack to preload login
    		if(url.endsWith("login")) {
    			if(login!=null)
    				view.loadUrl("javascript:document.getElementById('j_username').value = \""+login+"\";javascript:document.getElementById('j_password').focus();");
    		}
    	}
    	
        @Override
        public void onReceivedSslError (WebView view, SslErrorHandler handler, SslError error) {
        	// skip ssl error, for development only
        	Logd(TAG,"SSL error: "+error.toString());
            handler.proceed();
        }

        @Override
        public boolean shouldOverrideUrlLoading (WebView view, String url) {
            Logd(TAG, "shouldOverrideUrlLoading: "+url);
            // check if new url is specified redirect_uri
            if( m_redirect_uri != null && url.startsWith(m_redirect_uri) ) {
            	
            	// check if error
            	if( url.startsWith(m_redirect_uri+"?error") ) {
            		view.loadData("Error:<br>"+url.substring(m_redirect_uri.length()+1), "text/html", "UTF-8");
            		return true;
            	}
                Logd(TAG, "redirect: "+url);
                try {
                	// redirect url to remote service to handle token reception
                	if( remoteSI != null ) {
                		// TODO : display progress bar or hourglass
                        Logd(TAG, "sending back result 1");
                        remoteSI.doRedirect( id, url );
                	}
				} catch (Exception e) {
					e.printStackTrace();
				}
                
                // end of activity
                finish();
        		return true;
        	}
        	return false;
        }
    }

    @Override  
    public void onBackPressed() {
        cancelAction();
    }
    
    /** Called when the activity is about to be destroyed. */
	@Override
	protected void onDestroy() {
		releaseService();
		super.onDestroy();
	}
	
    @Override
    protected void onPause() {
        super.onPause();
        android.webkit.CookieSyncManager.getInstance().sync();
    }

    // logging utility, comment to avoid trace
	void Logd(String tag, String msg) {
		if(tag!=null && msg!=null) Log.d(tag, msg);
	}
}
