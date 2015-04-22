package com.orange.oidc.tim.hello;

import java.util.HashMap;
import java.util.Iterator;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

// utility class used to convert a JSON Userinfo response from a server
public class UserInfo {

	// map containing key, value pairs
	HashMap<String,String> infos = new HashMap<String, String>(); 
	
	// constructors
	public UserInfo() {};
	public UserInfo(String jsonString) {
		fromJsonString(jsonString);
	};
	
	// read an userinfo json string and extract each field
	void fromJsonString(String jsonString) {
		infos.clear();
        JSONObject jObject;
        try {
            jObject = new JSONObject(jsonString);
            JSONArray names = jObject.names();
            if(names!=null) {
	            for(int j=0; j<names.length(); j++)
	            {
	                String name  = names.getString(j);
	                String value = jObject.get(name).toString();
	                infos.put(name, value);
	            }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
	}
	
	// return all key pair values to a single string
	String toStr() {
		String s = "";
		Iterator<String> keys = infos.keySet().iterator();
		while(keys.hasNext()) {
			String k = keys.next();
			s += k+": "+infos.get(k)+"\n";
		}
		return s;
	}
	
	// get a particular value from a key
	String get(String key) {
		return infos.get(key);
	}
}
