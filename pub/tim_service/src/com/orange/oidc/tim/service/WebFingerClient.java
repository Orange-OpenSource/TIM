package com.orange.oidc.tim.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.X509Certificate;

import org.json.JSONObject;

import android.util.Log;


public class WebFingerClient {
	
	protected static final String TAG = "WebFingerClient";
	public String serverUrl = "https://192.168.0.100:8443/openid-connect-server-webapp";
	//URI identifying the type of service whose location is being requested
	String rel = "http://openid.net/specs/connect/1.0/issuer";
	//host server where a webfinger service is hosted
	String host ="";
	String href="";
	
	
	/**
     * return true if string is not null or empty, false otherwise
     * @param s
     * @return
     */
    private boolean isNotNullOrEmpty(String s) {
    	if(s==null || s.length()==0)
    		return false;
    	return true;
    }
    
    /**
     * Trust every server - dont check for any certificate
     */
    private static void trustAllHosts() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[] {};
            }

            public void checkClientTrusted(X509Certificate[] chain,
                                           String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain,
                                           String authType) throws CertificateException {
            }
        } };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // always verify the host - dont check for certificate
    final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
 	   @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
    
    
    static public HttpURLConnection getHUC(String address)
    {
        HttpURLConnection http = null;
        try {
            URL url = new URL(address);

            if (url.getProtocol().equalsIgnoreCase("https")) {
                trustAllHosts();
                HttpsURLConnection https = (HttpsURLConnection) url.openConnection();
                https.setHostnameVerifier(DO_NOT_VERIFY);
                http = https;
            } else {
                http = (HttpURLConnection) url.openConnection();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return http;
    }
   
    
    /**
     * Apply normalization rules to the identifier supplied by the End-User 
     * to determine the Resource and Host. Then make an HTTP GET request to
     * the host's WebFinger endpoint to obtain the location of the requested 
     * service
     * return the issuer location ("href")
     * @param user_input , domain
     * @return
     */
    
public String webfinger (String user_input, boolean Domain, String choice) {
    	
    	String result= ""; // result of the http request (a json object converted to string)
    	String postUrl = "";
    	
    	if(isNotNullOrEmpty(user_input)){
    		
    	
    		try {
    			//normalizes this URI's path
    			URI uri = new URI(user_input).normalize();
				String[] parts = uri.getRawSchemeSpecificPart().split("@");
				
				if(parts.length>1){
					//the user is using an E-Mail Address Syntax
					host=parts[parts.length-1];
				}else{
					//the user is using an other syntax
					host = uri.getHost();
				}
					
				
				if(Domain){
						postUrl = "https://"+host+"/.well-known/webfinger"
									+"?"+"resource="+user_input
									+"&"+"rel="+rel;
					
				}else{
					if(choice.equals("google")){
				
						//No domain so the request is hardcoded
						postUrl = "https://192.168.0.100:8443" + "/tim-gmail"+"/.well-known/webfinger"
								+"?"+"resource="+user_input
								+"&"+"rel="+rel;
					}else if(choice.equals("Orange")){
						postUrl = "https://192.168.0.100:8443" + "/tim-orange"+"/.well-known/webfinger"
							+"?"+"resource="+user_input
							+"&"+"rel="+rel;
					}else{
						postUrl = serverUrl + "/.well-known/webfinger"
							+"?"+"resource="+user_input
							+"&"+"rel="+rel;
					}
				}
				// log the request 
				Logd(TAG,"Web finger request\n GET "+postUrl + "\n HTTP /1.1" + "\n Host: "+ host);
			       //Send an HTTP get request with the resource and rel parameters
				   HttpURLConnection huc = getHUC(postUrl);
			       huc.setDoOutput(true);
			       huc.setRequestProperty("Content-Type","application/jrd+json");
			       huc.connect();
			    
			       
			       try {
			    	
		               int responseCode = huc.getResponseCode();
		               Logd(TAG, "webfinger responseCode: "+responseCode);
		            // if 200, read http body
		               if ( responseCode == 200 ) {
		                   InputStream is = huc.getInputStream();
		                   result= convertStreamToString(is);
		                   is.close();
		                   Logd(TAG, "webfinger result: "+result);
		                   
		       				// The response is a json object and the issuer location is returned as the value of the href member 
		                    // a links array element with the rel member value http://openid.net/specs/connect/1.0/issuer
		       				JSONObject jo = new JSONObject(result);
		       				JSONObject links = jo.getJSONArray("links").getJSONObject(0);
		       				href = links.getString("href");
		       				Logd(TAG, "webfinger reponse href: "+href);
		                   
		               }else{
		            	   //why the request didn't succeed
		            	   href=huc.getResponseMessage();
		               }
							
		               // close connection
		               huc.disconnect();
		           }catch(IOException ioe)
		           {
		               Logd(TAG,"webfinger io exception: "+huc.getErrorStream());
		               ioe.printStackTrace();
		           }
			       
    		} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		
    	}else {
    		//the user_input is empty
    		href= "no identifier detected!!\n";
    	}
		return href;
    }
    
    /**
   	 * To convert the InputStream to String we use the
   	 * BufferedReader.readLine() method. We iterate until the BufferedReader
   	 * return null which means there's no more data to read. Each line will
   	 * appended to a StringBuilder and returned as String.
   	 */
       public static String convertStreamToString(InputStream is) {
   		
   		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
   		StringBuilder sb = new StringBuilder();

   		String line = null;
   		try {
   			while ((line = reader.readLine()) != null) {
   				sb.append(line + "\n");
   			}
   		} catch (IOException e) {
   			e.printStackTrace();
   		} finally {
   			try {
   				is.close();
   			} catch (IOException e) {
   				e.printStackTrace();
   			}
   		}
   		return sb.toString();
   	} 

    void Logd(String tag, String msg) {
		if(tag!=null && msg!=null) Log.d(tag, msg);
	}
}
