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

import com.orange.oidc.tim.service.IRemoteListenerToken;

/**
 *
 */
interface IRemoteService {

    // public functions

    /**
    * ask tokens credential to a TIM enable AS ( Authorization Server )
    *
    * @param listener
    *           the token listener callback instance
    * @param serverUrl
    *           the URL of the authorization server
    * @param client_id
    *           the ID of client application on the authorization server
    * @param scope
    *           the information the application want to access
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OpenID Connect Core 1.0 documentation / Scope Claims</a>
    * @param state
    *           RECOMMENDED. Opaque value used to maintain state between the request and the callback.
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect Core 1.0 documentation / Auth Request</a>
    * @param nonce
    *           OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect Core 1.0 documentation / Auth Request</a>
    *           
    */
    void getTokensWithTim(
        IRemoteListenerToken listener,
        String serverUrl,
        String client_id,
        String scope, 
        String state, 
        String nonce );

    /**
    * refresh tokens if available
    *
    * @param serverUrl
    *           the URL of the authorization server
    * @param client_id
    *           the ID of client application on the authorization server
    * @param scope
    *           the information the application want to access
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OpenID Connect Core 1.0 documentation / Scope Claims</a>
    * 
    * @return
    *           a JSON string including the id_token and the tim_access_token
    *           or null if an error occured
    */
    String refreshTokenWithTim(
        String serverUrl,
        String client_id,
        String scope
        );


    /**
    * get a new TIM access token, signed by the SIM card
    * with its associate private key
    *
    * @param serverUrl
    *           the URL of the authorization server
    * @param client_id
    *           the ID of client application on the authorization server
    * @param scope
    *           the information the application want to access
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OpenID Connect Core 1.0 documentation / Scope claims</a>
    * 
    * @return
    *           the tim_access_token or null if an error occured
    */
    String getNewTimToken(
        String serverUrl,
        String client_id,
        String scope
        );

    /**
    * get user information on a resource server,
    * with a previously obtain TIM access token
    *
    * @param serverUrl
    *           the URL of the resource server
    * @param tim_access_token
    *           the access token needed to retrieve user informations
    * 
    * @return
    *           a JSON string returned by the resource server or null if an error occurred
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect Core 1.0 documentation / UserInfoResponse</a>
    */
    String getTimUserInfo(
        String serverUrl,
        String tim_access_token
        );

    /**
    * delete specified tokens
    *
    * @param serverUrl
    *           the URL of the authorization server
    * @param client_id
    *           the ID of client application on the authorization server
    * @param scope
    *           the information the application want to access
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OpenID Connect Core 1.0 documentation / Scope claims</a>
    * 
    * @return
    *           true if deleted, false if not found or an error occured
    */
    boolean deleteTokens(
        String serverUrl,
        String client_id,
        String scope
        );

    /**
    * Logout from the TIM and revoke tim_app_key on IdP and 3rd parties
    *
    * @param serverUrl
    *           the URL of the authorization server
    * @param client_id
    *           the ID of client application on the authorization server
    * @param scope
    *           the information the application want to access
    *           @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">OpenID Connect Core 1.0 documentation / Scope claims</a>
    * 
    * @return
    *           true if deleted, false if not found or an error occured
    */
    void revokeLogoutWithTim(
        String serverUrl,
        String client_id,
        String scope);

    /**
    * WebFinger discovers information for a URI that might not be usable as a locator otherwise, such as account or email URIs. 
    * to determine the host server.
    * @param userInput
    *           the data given by the user ( ie an email ) ( must not be null )
    * @param serverUrl
    *           the URL of the resource server, if not null, will request directly on the server
    * 
    * @return
    *           the server URL, null if error or not found
    *
    * if the 
    */
    String webFinger(
        String userInput,
        String serverUrl
        );


    /*
    *  openid connect methods, when used as a simple proxy only
    */
    
    // get tokens
    void getTokens(
        IRemoteListenerToken listener,
        String serverUrl,
        String client_id,
        String client_secret,
        String scope, 
        String redirect_uri, 
        String state, 
        String nonce 
        );
 
    // refresh tokens 
    String refreshToken(
        String serverUrl,
        String client_id,
        String client_secret,
        String scope, 
        String redirect_uri,
        String refresh_token
        );
 
    // get user info
    String getUserInfo(
        String serverUrl,
        String access_token
        );

    // Logout from the server
    void logout(String serverUrl);
}
