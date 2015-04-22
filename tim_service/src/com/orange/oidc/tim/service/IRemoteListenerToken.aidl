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

// IRemoteService.aidl
package com.orange.oidc.tim.service;

interface IRemoteListenerToken {

    /**
    * callback handler to a prior token request with tim
    *
    * @param id_token
    *           the id token
    * @param tim_access_token
    *           the tim access token
    * @param user_cancel
    *           true if user cancelled the operation, false otherwise
    *           
    */
    void handleTokenResponseWithTim (
        String id_token,
        String tim_access_token,
        boolean user_cancel
        );

    /**
    * callback handler to a prior token request
    *
    * @param tokens
    *           tokens as json
    *           can contain "cancel":"true" if cancelled by user
    *           
    */
    void handleTokenResponse ( String tokens );
}