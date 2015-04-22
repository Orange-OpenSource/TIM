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
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

import android.util.Base64;
import android.util.Log;

/**
 * class KryptoUtils
 * encrypt and decrypt function ( AES, RSA ... )
 * using spongy castle library
 *
 */
public class KryptoUtils {

	// get public key from big number inputs as string
	static PublicKey getRsaPublicKey(String n, String e) {
		BigInteger rsaN = null;
		BigInteger rsaE = null;

		try {
			rsaN = new BigInteger(n);
			rsaE = new BigInteger(e);
		} catch ( Exception ex) {
			ex.printStackTrace();
		}
		
		RSAPublicKeySpec pubRsaSpec = new RSAPublicKeySpec(rsaN, rsaE);
		try {
			KeyFactory keyfact = KeyFactory.getInstance("RSA","SC");
			PublicKey pk = keyfact.generatePublic(pubRsaSpec);
			Log.d("getRsaPublicKey","pubRsaKey OK "+pk.getFormat());
			return pk;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	// encode a byte array to a base64 string
	static String encodeB64(byte[] bytes) {
		try {
			return Base64.encodeToString(bytes, Base64.URL_SAFE|Base64.NO_PADDING|Base64.NO_WRAP );
		} catch (Exception e) {}
		return null;
	}

	// encode a byte array to a base64 string with no padding
	static String encodeB64NP(byte[] bytes) {
		return Base64.encodeToString(bytes, Base64.NO_PADDING );
	}

	// decode a byte array from a base64 string
	static byte [] decodeB64(String s64) {
		return Base64.decode(s64, Base64.URL_SAFE );
	}

	// decode a byte array from a base64 string with no padding
	static byte [] decodeB64NP(String s64) {
		return Base64.decode(s64, Base64.NO_PADDING );
	}

	// used for JWE : Json Web Encryption
	static final String jweHeader = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\",\"cty\":\"JWT\"}";
	static final String jweProtectedHeader = encodeB64(jweHeader.getBytes() );

	// random key generation
	// parameter should be a multiple of 8
	static byte[] generateRandomKey(int bitSize) {
		if(bitSize==0 || bitSize%8 != 0 )
			return null;
    	return new SecureRandom().generateSeed(bitSize/8);
    }

    // encode Key to a base64 string
	static String keyToBase64(Key k) {
		if(k!=null)
			return encodeB64(k.getEncoded());
		return null;
	}

	// decode a RSA private key from a base64 encoded string
	static Key base64ToRsaPrivateKey(String b64) {
		if(b64!=null) {
			try {
				byte[] keyBytes = decodeB64(b64);
				if ( keyBytes != null ) {
				    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
				    return  keyFactory.generatePrivate(privateKeySpec);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	// decode a RSA public key from a base64 encoded string
	static Key base64ToRsaPublicKey(String b64) {
		if(b64!=null) {
			try {
				byte[] keyBytes = decodeB64(b64);
				if ( keyBytes != null ) {
				    KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SC");
				    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
				    return keyFactory.generatePublic(publicKeySpec);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	// generate a RSA keypair ( public and private key ) 
	static KeyPair generateRsaKeyPair() {
		return generateRsaKeyPair(512);
	}

	// generate a RSA keypair ( public and private key ) 
	static KeyPair generateRsaKeyPair(int keySizeInBits) {
		if(keySizeInBits==0 || keySizeInBits%8 != 0 )
			return null;
		try {
		    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SC");
		    generator.initialize(keySizeInBits, new SecureRandom());

		    KeyPair pair = generator.generateKeyPair();

			// Log.d("","public : "+keyToBase64(pair.getPublic()));
			// Log.d("","private: "+keyToBase64(pair.getPrivate()));

		    return pair;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// encrypt a byte array using public rsa key
	// return result in base 64 encoded string
	static String encryptRsaB64(byte [] bytes, Key pubRsaKey) {
		try {
		    Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "SC");
		    // cipher.init(Cipher.ENCRYPT_MODE, pubRsaKey, new SecureRandom());
		    SecureRandom sc = null;
		    cipher.init(Cipher.ENCRYPT_MODE, pubRsaKey, sc);
		    byte[] cipherText = cipher.doFinal(bytes);
		    return encodeB64(cipherText );
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// decrypt a base 64 encoded string using private rsa key
	// return byte array
	static byte [] decryptRsaB64(String s64, Key privRsaKey) {
		try {
			byte[] sBytes = decodeB64( s64 );
			if ( sBytes != null ) {
			    Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "SC");
			    cipher.init(Cipher.DECRYPT_MODE, privRsaKey);
			    return cipher.doFinal(sBytes);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// encrypt a byte array using JWE ( Json Web Encryption )
	// if cek ( Content Encryption Key ) is null, a random 256 bits key is generated
	static String encryptJWE(byte [] bytes, Key pubRsaKey, byte[] cek) {
		// Log.d("","encryptJWE");
		try {
		    // A.2.1
		    // jwe header already computed as static
		    // jweProtectedHeader;
		    
		    // A.2.2 Content Encryption Key (CEK)
			if ( cek == null ) {
				cek = generateRandomKey(256);
			}
			
			// Log.d("","cek: "+bytesToHex(cek));
			
		    // A.2.3 Key Encryption
			String jweEncrypted64 = encryptRsaB64(cek, pubRsaKey);
			// Log.d("","jweEncrypted "+jweEncrypted64 );
		    
		    // A.2.4 Initialization Vector
			byte[] iv_key = generateRandomKey(128);
			
			// Log.d("","jweInitVector: "+bytesToHex(iv_key));
			String jweInitVector64 = encodeB64(iv_key);
			// Log.d("","jweInitVector64 "+jweInitVector64 );
			
		    // A.2.5 Additional Authenticated Data
			byte [] aad = jweProtectedHeader.getBytes();

			// A.2.6. Content Encryption
			Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");

			// check cek result byte array
			if( cek == null || cek.length == 0 || (cek.length%2)!=0 )
				return null;
			int keySize = cek.length/2;
			Log.d("","Encryption AES: "+keySize*8);
			
			byte aes_key []  = new byte[keySize];
			byte hmac_key [] = new byte[keySize];

			System.arraycopy(cek, 0,      hmac_key, 0, keySize);
			System.arraycopy(cek, keySize, aes_key, 0, keySize);

			// Log.d("","hmac_key: "+bytesToHex(hmac_key));
			// Log.d("","aes_key: "+bytesToHex(aes_key));

			encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes_key, "AES"), new IvParameterSpec(iv_key));
			byte[] cryptedBytes = encrypt.doFinal(bytes);
			String cryptedBytes64 = encodeB64(cryptedBytes);

			// compute hmac
			long al = aad.length * 8;

			// concatenate aad, iv_key, cryptedBytes and al 
			byte [] hmacData = new byte[aad.length+iv_key.length+cryptedBytes.length+8];
			int offset = 0;
			System.arraycopy(aad, offset, hmacData,  0, aad.length);
			offset += aad.length;
			System.arraycopy(iv_key, 0, hmacData,  offset, iv_key.length);
			offset += iv_key.length;
			System.arraycopy(cryptedBytes, 0, hmacData,  offset, cryptedBytes.length);
			offset += cryptedBytes.length;
		    ByteBuffer buffer = ByteBuffer.allocate(8);
		    buffer.putLong(al);
		    System.arraycopy(buffer.array(), 0, hmacData,  offset, 8);
			
			// hmac
			Mac hmac = Mac.getInstance("HmacSHA256","SC");
			hmac.init(new SecretKeySpec(hmac_key, "HmacSHA256"));
			byte [] hmacValue = hmac.doFinal(hmacData);
			
			// authentication tag
			byte [] auth_tag = Arrays.copyOf(hmacValue, 16); 
			String auth_tag64 = encodeB64(auth_tag );
			
			// A.2.7. Complete Representation
			String finalString = 
					jweProtectedHeader + "." +
					jweEncrypted64 + "." +
					jweInitVector64 + "." +
					cryptedBytes64 + "." +
					auth_tag64;

			return finalString;
			
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	// decrypt a byte array from JWE string
	static byte [] decryptJWE(String jwe, Key privRsaKey) {
		// Log.d("","decryptJWE");
		
		try {
			// split jwe string
			StringTokenizer tokens = new StringTokenizer(jwe, ".");
			int count = tokens.countTokens();
			// Log.d("","parts.length: "+count);
			
			if( count != 5 )
				return null;
			
			String jweProtectedHeader64 = tokens.nextToken();
			String jweEncrypted64       = tokens.nextToken();
			String jweInitVector64      = tokens.nextToken();
			String cryptedBytes64       = tokens.nextToken();
			String auth_tag64           = tokens.nextToken();

			// decrypt cek using private rsa key
			byte [] cek = decryptRsaB64( jweEncrypted64,privRsaKey);

			// check cek result byte array
			if( cek == null || cek.length == 0 || (cek.length%2)!=0 )
				return null;

			int keySize = cek.length / 2;
			Log.d("","Decryption AES: "+keySize*8);
			
			// build aes_key and hmac_key
			byte aes_key  [] = new byte[keySize];
			byte hmac_key [] = new byte[keySize];
			
			System.arraycopy(cek, 0,       hmac_key, 0, keySize);
			System.arraycopy(cek, keySize, aes_key,  0, keySize);

			// decode initialization vector
			byte[] iv_key = decodeB64(jweInitVector64 );

			Log.d("","hmac_key: "+bytesToHex(hmac_key));
			Log.d("","aes_key:  "+bytesToHex(aes_key));
			Log.d("","iv_key:   "+bytesToHex(iv_key));


			// decrypt content using aes_key and iv_key
			byte [] cryptedBytes = decodeB64(cryptedBytes64);
			Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "SC");
			decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes_key, "AES"), new IvParameterSpec(iv_key));
			byte[] decryptedBytes = decrypt.doFinal(cryptedBytes);

			Log.d("","decryptedBytes:");
			Log.d("",bytesToHex(decryptedBytes));
			
			// validation verification
			byte [] aad = jweProtectedHeader64.getBytes();
			long al = aad.length * 8;
			
			// concatenate aad, iv_key, cryptedBytes and al 
			byte [] hmacData = new byte[aad.length+iv_key.length+cryptedBytes.length+8];
			int offset = 0;
			System.arraycopy(aad, offset, hmacData,  0, aad.length);
			offset += aad.length;
			System.arraycopy(iv_key, 0, hmacData,  offset, iv_key.length);
			offset += iv_key.length;
			System.arraycopy(cryptedBytes, 0, hmacData,  offset, cryptedBytes.length);
			offset += cryptedBytes.length;
		    ByteBuffer buffer = ByteBuffer.allocate(8);
		    buffer.putLong(al);
		    System.arraycopy(buffer.array(), 0, hmacData,  offset, 8);

		    // compute hmac
			Mac hmac = Mac.getInstance("HmacSHA256","SC");
			hmac.init(new SecretKeySpec(hmac_key, "HmacSHA256"));
			byte [] hmacValue = hmac.doFinal(hmacData);
			
			// pick authentication tag
			byte [] authTag     = Arrays.copyOf(hmacValue, 16); 

			// validate authentication tag
			byte [] authTagRead = decodeB64(auth_tag64 );
			for(int i=0; i<16; i++) {
				if(authTag[i] != authTagRead[i]) {
					Log.d("","validation failed");
					return decryptedBytes;
				}
			}

			Log.d("","validation success");

			// validation success
			return decryptedBytes;
			
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	// get Base64 encoded signature for specified string data, key and algorithm
	static public String getSignature(String s, RSAPrivateKey privKey, String algorithm) {
		try {
			if("RS256".compareTo(algorithm)==0)
				algorithm = "SHA256withRSA";
			Signature signature = Signature.getInstance(algorithm,"SC");
	        signature.initSign(privKey);
	        signature.update(s.getBytes(Charset.forName("UTF-8")));
	        byte [] signed = signature.sign();
	        return encodeB64(signed);
		} catch ( Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// sign a JWS string, with specified private key
	static public String signJWS(String s, String signHeader, String algorithm, RSAPrivateKey privKey) {
		String header64 = encodeB64(signHeader.getBytes());
		
		String signature = getSignature(header64+"."+s,privKey,algorithm);
		if(signature!=null)
			return 	header64 + "." + s + "." + signature;
		return null;
	}
	
	// verify a JWS string with specified keys
	static public boolean verifyJWS(String s, String algorithm, PublicKey pubKey, PrivateKey privKey) {
        // algorithm = "SHA256withRSA";
        // algorithm = "SHA1withRSA";

		boolean bverify = false;

		String parts[] = s.split("\\.");
        if(parts==null || parts.length != 3) return bverify;
        
		try {
			if("RS256".compareTo(algorithm)==0)
				algorithm = "SHA256withRSA";
			Signature signature = Signature.getInstance(algorithm,"SC");
	        signature.initVerify(pubKey);
	        signature.update((parts[0]+"."+parts[1]).getBytes());
	        bverify = signature.verify(decodeB64(parts[2]));

	        Log.d("verifyJWS","payload: "+new String(decodeB64(parts[1])));
	        /*
	        // verify signature
	        signature.initSign(privKey);
	        signature.update((parts[0]+"."+parts[1]).getBytes());
	        byte sig[] = signature.sign();
	        String sig64 = encodeB64(sig);
	        Log.d("verifyJWS","compute: "+sig64);
	        Log.d("verifyJWS","SIM    : "+parts[2]);
	        */

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return bverify;
	}
	
	// BYTE to HEX STRING conversion and vice versa

	static String bytesToString(byte [] bytes) {
		if( bytes != null ) {
			String s="[ ";
			for(int i=0; i<bytes.length; i++) {
				s += bytes[i];
				if((i+1)==bytes.length) {
					s += " ]";
				} else {
					s += ", ";
				}
			}
			return s;
		}
		return null;
	}
	
	final protected static char[] hexArrayM = "0123456789ABCDEF".toCharArray();
	final protected static char[] hexArraym = "0123456789abcdef".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		int nSize = 2; // 3;
	    char[] hexChars = new char[bytes.length * nSize];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * nSize] = hexArrayM[v >>> 4];
	        hexChars[j * nSize + 1] = hexArrayM[v & 0x0F];
	        // hexChars[j * nSize + 2] = ' ';
	    }

	    return new String(hexChars);
	}

	// utility to convert byte arrays to it string representation, with an optional separator
	public static String bytesToHex(byte[] bytes, String sep) {
		if(sep==null) sep="";
		
		int nSize = 2; // 3;
	    StringBuffer sb = new StringBuffer((bytes.length+sep.length()) * nSize);
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        sb.append(sep);
	        sb.append(hexArrayM[v >>> 4]);
	        sb.append(hexArrayM[v & 0x0F]);
	    }

	    return sb.toString();
	}

	// convert a byte to its string representation in hexa
	public static String byteToHex(byte b) {
		int v = b & 0xFF;
        return  "" + hexArrayM[v >>> 4] + hexArrayM[v & 0x0F];
	}
	
	// convert a short integer to its string representation in hexa
	public static String shortToHex(int i) {
		return ""+byteToHex((byte)((i&0xFF00)>>>8))+byteToHex((byte)(i&0xFF));
	}
	
	public static String bytesToHexm(byte[] bytes) {
		int nSize = 2; // 3;
	    char[] hexChars = new char[bytes.length * nSize];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * nSize] = hexArraym[v >>> 4];
	        hexChars[j * nSize + 1] = hexArraym[v & 0x0F];
	        // hexChars[j * nSize + 2] = ' ';
	    }

	    return new String(hexChars);
	}

	// utility to convert an hexa display string to its corresponding byte array
	final static byte [] hexByte = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
									 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; 
	
	public static byte [] hexToBytes(String hex) {
        // android.os.Debug.waitForDebugger();

		if(hex==null || hex.length()<2)
			return null;

		int hexLength = hex.length()/2;
		byte [] hexb = new byte [hexLength];
		for(int i=0; i<hexLength; i++) {
			char a = hex.charAt(2*i);
			char b = hex.charAt(1+2*i);
			
			byte ba=0,bb=0;
			
			if( a >='0' && a <= '9')
				ba = (byte) (a - '0');
			else if( a >='A' && a <= 'F')
				ba = (byte) (0x0A + a - 'A');

			if( b >='0' && b <= '9')
				bb = (byte) (b - '0');
			else if( b >='A' && b <= 'F')
				bb = (byte) (0x0A + a - 'A');
			
			hexb[i] = (byte) (ba << 8 | bb);
		}

		return hexb;
	}
	
	// get a JWK string with public key from a previously generated keypair
	public static String getJwkPublic(KeyPair kp) {
    	try {
        	JSONObject jk = new JSONObject();
			jk.put("kty", "RSA");
            // generate random kid for tim_app_key
            SecureRandom random = new SecureRandom();
            String kid = new BigInteger(130, random).toString(32);
			jk.put("kid", kid);
			jk.put("e", "AQAB");

        	KeyFactory kfactory = KeyFactory.getInstance("RSA");

	        RSAPublicKeySpec kspec = (RSAPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
			
			jk.put("n", encodeB64(kspec.getModulus().toByteArray()));
        	JSONArray ja = new JSONArray();
        	ja.put(jk);
        	JSONObject jo = new JSONObject();
        	jo.put("keys", ja);

        	// Log.d("getJwkPublic key: ",pubkey.toString());
        	// Log.d("getJwkPublic jwk: ",jo.toString());
        	
        	return jo.toString();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    	
		return null;
	}

	// get a JWK string with private key from a previously generated keypair
	public static String getJwkPrivate(KeyPair kp) {
    	try {
        	JSONObject jk = new JSONObject();
			jk.put("kty", "RSA");
            // generate random kid for tim_app_key
            SecureRandom random = new SecureRandom();
            String kid = new BigInteger(130, random).toString(32);
            jk.put("kid", kid);
			jk.put("e", "AQAB");

        	KeyFactory kfactory = KeyFactory.getInstance("RSA");
        	
        	RSAPrivateKeySpec privkspec = (RSAPrivateKeySpec) kfactory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
	        RSAPublicKeySpec  pubkspec = (RSAPublicKeySpec) kfactory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);

        	// Log.d("getJwkPrivate n",pubkspec.getPublicExponent().toString());
        	// Log.d("getJwkPrivate d",privkspec.getPrivateExponent().toString());
			
			jk.put("n", encodeB64(pubkspec.getModulus().toByteArray()));
			jk.put("d", encodeB64(privkspec.getPrivateExponent().toByteArray()));
        	JSONArray ja = new JSONArray();
        	ja.put(jk);
        	JSONObject jo = new JSONObject();
        	jo.put("keys", ja);

        	return jo.toString();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// parse a JWK string to extract private key
	public static RSAPrivateKey privKeyFromJwk(String jwkp) {
		RSAPrivateKey privKey = null;

		try {
			JSONObject jk = new JSONObject(jwkp).getJSONArray("keys").getJSONObject(0);
				
			BigInteger n = new BigInteger(1, decodeB64(jk.getString("n")));
			BigInteger d = new BigInteger(1, decodeB64(jk.getString("d")));
			// BigInteger e = new BigInteger(1, decodeB64(jk.getString("e")));

			// Log.d("privKeyFromJwk","n "+n);
			// Log.d("privKeyFromJwk","d "+d);
			// Log.d("privKeyFromJwk","e "+e);
			
			RSAPrivateKeySpec privRsaSpec = new RSAPrivateKeySpec(n, d);
			KeyFactory keyfact = KeyFactory.getInstance("RSA","SC");
			privKey = (RSAPrivateKey)keyfact.generatePrivate(privRsaSpec);
			// Log.d("privKeyFromJwk","priv key length "+privRsaSpec.getModulus().toByteArray().length);
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return privKey;
	}
	
    // get the kid of a jwk
    public static String kidFromJwk(String jwkp) {
        String kid ="";
        try {
            JSONObject jk = new JSONObject(jwkp).getJSONArray("keys").getJSONObject(0);
            kid = jk.getString("kid");
            Log.d("kidFromJwk","kid "+kid);
         } catch (Exception e) {
            e.printStackTrace();
        }
        return kid;
    }
	
	// parse a JWK string to extract public key
	public static PublicKey pubKeyFromJwk(String jwkp) {
		PublicKey pubKey = null;

		try {
			JSONObject jk = new JSONObject(jwkp).getJSONArray("keys").getJSONObject(0);
				
			BigInteger n = new BigInteger(1, decodeB64(jk.getString("n")));
			BigInteger e = new BigInteger(1, decodeB64(jk.getString("e")));

			// Log.d("pubKeyFromJwk","n "+n);
			// Log.d("pubKeyFromJwk","e "+e);
			
			RSAPublicKeySpec pubRsaSpec = new RSAPublicKeySpec(n, e);
			KeyFactory keyfact = KeyFactory.getInstance("RSA","SC");
			pubKey = keyfact.generatePublic(pubRsaSpec);
			// Log.d("pubKeyFromJwk","pub key length "+pubRsaSpec.getModulus().toByteArray().length);
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return pubKey;
	}

	// as our SIM card does not support HmacSHA256 algorithm
	public static String completeJweFromSIM( String jweSIM ) {
        // android.os.Debug.waitForDebugger();

		try {
			if(jweSIM!=null && jweSIM.length()>0) {
				String parts [] = jweSIM.split("\\.");;
				if(parts!=null && parts.length==5) {
					// retrieve hmac key
					byte hmac_key[] = Base64.decode(parts[4], Base64.URL_SAFE);
					if(hmac_key!=null && hmac_key.length==16) {
						// init hash instance
						Mac hmac = Mac.getInstance("HmacSHA256","SC");
						hmac.init(new SecretKeySpec(hmac_key, "HmacSHA256"));
						
						byte[] aad    = parts[0].getBytes();
						long al = aad.length * 8;
						byte[] iv_key = decodeB64(parts[2]);
						byte[] cryptedBytes = decodeB64(parts[3]);
						
						// build data to hash
						byte [] hmacData = new byte[aad.length+iv_key.length+cryptedBytes.length+8];
						int offset = 0;
						System.arraycopy(aad, offset, hmacData,  0, aad.length);
						offset += aad.length;
						System.arraycopy(iv_key, 0, hmacData,  offset, iv_key.length);
						offset += iv_key.length;
						System.arraycopy(cryptedBytes, 0, hmacData,  offset, cryptedBytes.length);
						offset += cryptedBytes.length;
					    ByteBuffer buffer = ByteBuffer.allocate(8);
					    buffer.putLong(al);
					    System.arraycopy(buffer.array(), 0, hmacData,  offset, 8);
						
						// compute hac value
						byte [] hmacValue = hmac.doFinal(hmacData);
						// authentication tag
						byte [] auth_tag = Arrays.copyOf(hmacValue, 16); 
						String auth_tag64 = encodeB64(auth_tag );
						
						// A.2.7. Complete Representation
						String finalString = 
								parts[0] + "." +
								parts[1] + "." +
								parts[2] + "." +
								parts[3] + "." +
								auth_tag64;

//						// just for verification
//						byte jwt64 [] = decryptJWE(finalString, RsaKeyTim.privRsaKey);
//						if(jwt64!=null) {
//							String jws = new String(jwt64);
//							Log.d("completeJweFromSIM", "jws verify Key TIM :"+verifyJWS(jws,RsaKeyTim.pubRsaKey));
//						}

						return finalString;
					}
				}
				// 
			}
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
