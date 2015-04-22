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
import java.io.IOException;
import java.io.OutputStream;

/*
 * class OpenidConnectParams
 * used to regroup all parameters that defines an open id connect server 
 */
public class OpenidConnectParams {

	// openid specific
	public String m_server_url;
	public String m_client_id;
	public String m_scope;
	public String m_response_type;
	public String m_state;
	public String m_nonce;
	public String m_redirect_uri;
	public String m_client_secret;
	public String m_server_scope;

	// TIM specific
	public String m_request = "tim&app_id=app_id&tim_app_key=app_key";

	// optional and reserved
	public String m_jwk;
	
	// constructors
	public OpenidConnectParams() {}
	public OpenidConnectParams(OpenidConnectParams ocp) {
		init(ocp);
	}
	public OpenidConnectParams(String serverUrl, String client_id, String scope, String redirect_uri,
			String state, String nonce, String responseType, String client_secret, String server_scope) {
		init(serverUrl, client_id, scope, redirect_uri, state, nonce, responseType, client_secret, server_scope);
	}
	public OpenidConnectParams(String serverUrl, String client_id, String scope, String redirect_uri) {
		init(serverUrl, client_id, scope, redirect_uri, null, null, null, null, null);
	}
	
	// init object with multiple params
	void init(String serverUrl, String client_id, String scope, String redirect_uri,
			  String state, String nonce, String responseType, String client_secret, String server_scope ) {
		m_server_url=serverUrl;
		m_client_id=client_id;
		m_scope=scope;
		m_redirect_uri=redirect_uri;
		m_response_type=responseType;
		m_state=state;
		m_nonce=nonce;
		m_client_secret=client_secret;
		m_nonce=nonce;
		m_server_scope = server_scope;
	}

	// copy an object params
	void init(OpenidConnectParams ocp) {
		init(ocp.m_server_url, ocp.m_client_id, ocp.m_scope, ocp.m_redirect_uri,
		     ocp.m_state, ocp.m_nonce, ocp.m_response_type, ocp.m_client_secret, ocp.m_server_scope);
	}
	
	// read params from a buffer
	boolean read(BufferedReader reader) {
		try {
			m_server_url    = reader.readLine();
			m_response_type = reader.readLine();
			m_scope         = reader.readLine();
			m_state         = reader.readLine();
			m_nonce         = reader.readLine();
			m_redirect_uri  = reader.readLine();
			m_client_id     = reader.readLine();
			m_client_secret = reader.readLine();
			return true;
		} catch ( IOException e ) {
			e.printStackTrace();
		}
		return false;
	}

	// write params to a buffer
	boolean write(OutputStream s) {
		try {
			writeString(s,m_server_url);
			writeString(s,m_response_type);
			writeString(s,m_scope);
			writeString(s,m_state);
			writeString(s,m_nonce);
			writeString(s,m_redirect_uri);
			writeString(s,m_client_id);
			writeString(s,m_client_secret);
			return true;
		} catch ( IOException e ) {
			e.printStackTrace();
		}
		return false;
	}
	
	// write a string to a stream
	void writeString(OutputStream s, String p)
		throws IOException {
		if(p==null || p.length()==0) {
			s.write("".getBytes());
		}
		else {
			s.write(p.getBytes());
		}
		s.write("\n".getBytes());
	}

	// return all params as a single string
	public String toString() {
		return
			m_server_url + " /*/ " +
			m_response_type+ " /*/ " +
			m_scope+ " /*/ " +
			m_state+ " /*/ " +
			m_nonce+ " /*/ " +
			m_redirect_uri+ " /*/ " +
			m_client_id + " /*/ " +
			m_client_secret ;
	}
}
