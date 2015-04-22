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

import java.security.PublicKey;
import java.util.Calendar;

/**
 * 
 * SecureStorage interface
 * used to generate crypted and signed request objects
 * and to store tokens and generate tim access tokens
 *
 */
abstract public class TimSecureStorage {

	public abstract String getClientId();

	public abstract String getRedirectUri();
	
	public abstract String save_tokens(
			OpenidConnectParams ocp,
			String id_token,
			String refresh_token,
			String expires_in);
			
    public abstract TokensKeys read_tokens(
    		String server_url,
    		String client_id,
    		String scope );

    public abstract boolean delete_tokens(
    		String server_url,
    		String client_id,
    		String scope );

    public abstract String update_tokens(OpenidConnectParams ocp, String id_token, String refresh_token, String expires);

	public abstract TokensKeys genTimAppKey( OpenidConnectParams ocp );

	public abstract String getNewTimToken( OpenidConnectParams ocp );

	public abstract String getTimRequestObject(
			String server_url,
			String client_id,
			String scope,
			PublicKey serverPubKey
			);

		// convert a json string "expires_in" to a base64 string representing its time in ms
	public static String convertExpiresIn(String expires_in) {
		try {
			int expires = Integer.parseInt(expires_in);
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.SECOND, expires);
            return String.valueOf(cal.getTimeInMillis()/1000);
			//return KryptoUtils.encodeB64( Long.toHexString(cal.getTimeInMillis()).getBytes() );
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}

	public abstract String getPrivateKeyJwt(String token_endpoint);
	public abstract String getClientSecretBasic();
}
