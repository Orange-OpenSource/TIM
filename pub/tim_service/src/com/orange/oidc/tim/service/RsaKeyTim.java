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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

// RSA key used by the TIM
// here for demo only, must be stored in a secure element
class RsaKeyTim {

	// RSA 512
	static private String _rsaNs = "10003190979582651350655152244004345890631015214818181537786763230713471231853499869807883467394056677198764505889961899609697526623820585440838924851122131";
	static private String _rsaDs = "8266671093492170791331355502010701946024013672193611426927248677471376503611314512710786540172282771004573025670257705631085683716365421687136951057439233";
	static private String _rsaEs = "65537";

	static public  RSAPrivateKey privRsaKey;
	static public  PublicKey pubRsaKey;
	
	// init the key from the big numbers above
	static {
		BigInteger rsaN = null;
		BigInteger rsaE = null;
		BigInteger rsaD = null;
		try {
			rsaN = new BigInteger(_rsaNs);
			rsaD = new BigInteger(_rsaDs);
			rsaE = new BigInteger(_rsaEs);
		} catch ( Exception e) {
			e.printStackTrace();
		}
		
		RSAPrivateKeySpec privRsaSpec = new RSAPrivateKeySpec(rsaN, rsaD);
		RSAPublicKeySpec pubRsaSpec = new RSAPublicKeySpec(rsaN, rsaE);
		pubRsaKey = null;
		privRsaKey = null;
		try {
			KeyFactory keyfact = KeyFactory.getInstance("RSA","SC");
			pubRsaKey = keyfact.generatePublic(pubRsaSpec);
	        
        	KeyFactory kfactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec kspec = (RSAPublicKeySpec) kfactory.getKeySpec(pubRsaKey, RSAPublicKeySpec.class);
			
			Logd("RsaKeyTim","TIM pubRsaKey OK "+kspec.getModulus().toByteArray().length);
	        
	        privRsaKey = (RSAPrivateKey) keyfact.generatePrivate(privRsaSpec);
			Logd("RsaKeyTim","TIM privRsaKey OK "+privRsaKey.getFormat());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static void Logd(String tag, String msg) {
		// if(tag!=null && msg!=null) android.util.Log.d(tag, msg);
	}
}
