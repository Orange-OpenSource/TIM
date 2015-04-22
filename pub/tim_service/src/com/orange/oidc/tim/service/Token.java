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

import java.util.Calendar;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Base64;
import android.util.Log;

public class Token {

	String iss;
	String sub;
	String aud;
	String jti;
	String exp;
	String iat;
	String auth_time;
	String nonce;
	String at_hash;
	String acr;
	String amr;
	String azp;
	String tak; // tim app key
	
	public Token() {}
	public Token(String token) {
		fromToken(token);
	}
	
	void reset() {
		iss=null;
		sub=null;
		aud=null;
		jti=null;
		exp=null;
		iat=null;
		auth_time=null;
		nonce=null;
		at_hash=null;
		acr=null;
		amr=null;
		azp=null;
		tak=null;
	}
	
	static String getJSON(String token) {
        String ds = null;
		
        String tokenB64 = null;
        if ( token != null ) {
			String [] p = token.split("\\.");
			if( p!=null && p.length == 3) {
				tokenB64 = p[1];
			}
		}

		if ( tokenB64 != null ) {
	        byte []decoded = null;
	        try {
	            decoded = Base64.decode(tokenB64, Base64.URL_SAFE);
	            ds = new String(decoded, "UTF-8");
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        if(decoded==null) {
	            try {
	                decoded = Base64.decode(tokenB64, Base64.DEFAULT);
	                ds = new String(decoded, "UTF-8");
	            } catch (Exception ee) {
	                // TODO Auto-generated catch block
	                ee.printStackTrace();
	            }
	        }
		}
		return ds;
	}
	
	public void fromToken(String token) {
		reset();
		if(token==null) return;
		
        try {
    		JSONObject jObject = null;
    		
    		// try token as is
    		try {
	        	jObject = new JSONObject(token);
    		} catch (Exception e) {}

    		// try to decode JWT
    		if( jObject == null ) {
    			String ds = getJSON(token);
    			if(ds!=null)
    				jObject = new JSONObject(ds);
    		}

    		if(jObject!=null) {
	            JSONArray names = jObject.names();
	    		if(names!=null) {
		            for(int j=0; j<names.length(); j++)
		            {
		                String name = names.getString(j);
		        		// Log.d("Token",name);
		                setField(name,jObject.get(name));
		            }
	    		}
    		}
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
	}
	
	void setField(String name, Object object) {
		if(name==null || name.length()==0) return;
		
		if(name.compareTo("iss")==0) {
			iss = (String)object;
		} else if(name.compareTo("sub")==0) {
			sub = (String)object;
		} else if(name.compareTo("aud")==0) {
			JSONArray jArray = (JSONArray)object; 
			aud = "";
			for(int i=0; i<jArray.length(); i++){
				try {
					aud += jArray.getString(i)+" ";
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		} else if(name.compareTo("jti")==0) {
			jti = (String)object;
		} else if(name.compareTo("exp")==0) {
			exp = getIntAsString(object);
		} else if(name.compareTo("iat")==0) {
			iat = getIntAsString(object);
		} else if(name.compareTo("auth_time")==0) {
			auth_time = getIntAsString(object);
		} else if(name.compareTo("nonce")==0) {
			nonce = (String)object;
		} else if(name.compareTo("at_hash")==0) {
			at_hash = (String)object;
		} else if(name.compareTo("acr")==0) {
			acr = (String)object;
		} else if(name.compareTo("amr")==0) {
			amr = (String)object;
		} else if(name.compareTo("azp")==0) {
			azp = (String)object;
		} else if(name.compareTo("tim_app_key")==0) {
			tak = (String)object;
		}
	}
	
	String getIntAsString(Object o) {
		try {
			return ((Integer)o).toString();
		} catch(Exception e) {
			try {
				return (String)o;
			} catch(Exception ee) {
			}
		}
		return null;
	}
	
	String fromCal(Calendar c) {
		if(c!=null) {
			return c.get(Calendar.DAY_OF_MONTH) + "/" +
					c.get(Calendar.MONTH) + "/" +
					c.get(Calendar.YEAR) + " " +
					c.get(Calendar.HOUR_OF_DAY) + ":" +
					c.get(Calendar.MINUTE) + ":" +
					c.get(Calendar.SECOND);
		}
		return null;
	}
	
	boolean isExpired() {
		Calendar cal = getExp();
		if( cal!=null )
			Log.d("Token","expiration: "+fromCal(cal));
		if( cal!=null && cal.after(Calendar.getInstance())) {
			return false;
		}
		return true;
	}

	Calendar getExp() {
		return fromStringToDate(exp);
	}
	
	Calendar getIat() {
		return fromStringToDate(iat);
	}

	Calendar getAuthTime() {
		return fromStringToDate(auth_time);
	}

	Calendar fromStringToDate(String s) {
		if(s!=null && s.length()>0) {
			try {
				long d = Long.parseLong(s);
				Calendar c = Calendar.getInstance();
				c.setTimeInMillis(d*1000);
				c.setTimeZone(TimeZone.getDefault());
				return c;
				
			} catch ( Exception e ) {
			}
		}
		return null;
	}
}
