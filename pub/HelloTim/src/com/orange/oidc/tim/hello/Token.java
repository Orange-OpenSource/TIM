package com.orange.oidc.tim.hello;

import java.util.Calendar;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Base64;
import android.util.Log;

// Token utility class - decrypt and read known fields
public class Token {

	String iss;			// issuer identifier
	String sub;			// subject identifier
	String aud;			// audience
	String jti;			// JWT ID
	String exp;			// expiration time
	String iat;			// issued at time
	String auth_time;	// authentication time
	String nonce;		// value to mitigate replay attacks
	String at_hash;		// Access Token hash value
	String acr;			// Authentication Context Class Reference 
	String amr;			// Authentication Methods References 
	String azp;			// Authorized party 
	String tak;			// tim app key
	
	// constructors
	public Token() {}
	public Token(String token) {
		fromToken(token);
	}
	
	// clear values
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
	
	// return the decoded part of a JWT object
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
	            e.printStackTrace();
	        }
	        if(decoded==null) {
	            try {
	                decoded = Base64.decode(tokenB64, Base64.DEFAULT);
	                ds = new String(decoded, "UTF-8");
	            } catch (Exception ee) {
	                ee.printStackTrace();
	            }
	        }
		}
		return ds;
	}
	
	// init a Token object from a JWT string
	public void fromToken(String token) {
		reset();
		if(token==null) return;
		
        try {
    		String ds = getJSON(token);
    		if(ds!=null) {
	        	JSONObject jObject = new JSONObject(ds);
	    		if(jObject!=null) {
		            JSONArray names = jObject.names();
		    		if(names!=null) {
			            for(int j=0; j<names.length(); j++)
			            {
			                String name = names.getString(j);
			        		Log.d("Token",name);
			                setField(name,jObject.get(name));
			            }
		    		}
	    		}
    		}
        } catch (JSONException e) {
            e.printStackTrace();
        }
	}
	
	// set field value for each known members
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
					e.printStackTrace();
				}
			}
		} else if(name.compareTo("jti")==0) {
			jti = (String)object;
		} else if(name.compareTo("exp")==0) {
			exp = (String)object;
		} else if(name.compareTo("iat")==0) {
			iat = (String)object;
		} else if(name.compareTo("auth_time")==0) {
			auth_time = (String)object;
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
	
	// return a human readable date from a Calendar object
	static String fromCal(Calendar c) {
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
	
	// check if token has expired
	boolean isExpired() {
		Calendar cal = getExp();
		if( cal!=null )
			Log.d("Token","expiration: "+fromCal(cal));
		if( cal!=null && cal.after(Calendar.getInstance())) {
			return false;
		}
		return true;
	}

	// get token expiration time
	Calendar getExp() {
		return fromStringToDate(exp);
	}
	
	// get token issued time
	Calendar getIat() {
		return fromStringToDate(iat);
	}

	// get token user authentication time
	Calendar getAuthTime() {
		return fromStringToDate(auth_time);
	}

	// convert a string containing a long value to a calendar object
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
