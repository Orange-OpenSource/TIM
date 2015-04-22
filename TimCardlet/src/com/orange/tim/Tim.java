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

package com.orange.tim;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class Tim extends Applet {
	
	final byte TIM_SIM_VERSION = 0x02;
	
	// code of CLA byte in the command APDU header
    final static byte TIM_CLA         = (byte) 0x80;
    
    // codes of INS byte in the command APDU header
    final static byte STORE_DATA      = (byte) 0x20;
    final static byte GET_DATA        = (byte) 0x30;
    final static byte CHECK_AR        = (byte) 0x40;
    final static byte AUTH_USER       = (byte) 0x50;
    final static byte MAKE_DATA       = (byte) 0x51;
    
    // code of P1 and P2 parameters for the instruction
    
    // INS: STORE_DATA, possible values for P1
    // final static byte SET_TIME           = (byte) 0x01;
    final static byte SET_TOKENS         = (byte) 0x02;
    final static byte SET_USERINFO       = (byte) 0x03;
    final static byte SET_APP_REQ        = (byte) 0x04;
    // final static byte SET_ID_TOKEN       = (byte) 0x05;
    // final static byte SET_REFRESH_TOKEN  = (byte) 0x06;
    // final static byte SET_REQUEST_OBJECT = (byte) 0x07;
    // final static byte SET_TIM_TOKEN      = (byte) 0x08;
    final static byte UPDATE_TOKENS      = (byte) 0x09;
    final static byte SET_RESET          = (byte) 0x10;
    final static byte DELETE_TOKENS_KEY  = (byte) 0x11;
    final static byte SET_ENCRYPT_DATA   = (byte) 0x12;
    
    // INS: GET_DATA, possible values for P1
    final static byte GET_TIM_ID        = (byte)0x01;
    final static byte GET_TIM_RO        = (byte)0x02;
    final static byte GET_REFRESH_TOKEN_WITH_TIM_APP_KEY = (byte)0x03;
    final static byte GET_ACCESS_TOKEN  = (byte)0x04;
    final static byte GET_USER_INFO     = (byte)0x05;

    final static byte GET_TOKENS_KEY    = (byte)0x07;
    
    final static byte GET_FREE_SPACE    = (byte)0x09;
    final static byte GET_TIM_SECRET    = (byte)0x0A;

    final static byte GET_PUB_KEY       = (byte)0x10;
    final static byte GET_TOKENS        = (byte)0x11;
    final static byte GET_TIM_TKN_SIGN  = (byte)0x12;
    final static byte SEARCH_TOKENS     = (byte)0x13;

    final static byte GET_ALL           = (byte)0x20;
    final static byte GET_TK_ALL        = (byte)0x21;
    final static byte GET_APP_REQ       = (byte)0x22;

    final static byte GET_ENCRYPTED_TIM = (byte)0x23;
    final static byte GET_ENCRYPTED_TAK = (byte)0x24;

    final static byte GET_VERSION       = (byte)0xF0;


    // INS : MAKE_DATA, possible values for P1
    final static byte GEN_TIM_APP_KEY  = (byte) 0x01;
    
    //Status word code for the error
    
    final static short SW_ERROR_SETTING_TIME = (short) 0x9011;
    final static short SW_NO_CACHED_REQUEST = (short) 0x9012;
    final static short SW_EXP_TOKEN = (short) 0x9013;
    
    final static short SW_WAITFOR_DATA = (short) 0x9014;

    
    // SHORT NUMBERS ...
	static final short ZERO = (short) 0;
	static final short ONE  = (short) 1;
	static final short TWO  = (short) 2;
	static final short THREE= (short) 3;
	static final short FOUR = (short) 4;

    
	// SECRET VALUES
	final static byte [] TIM_ID = { (byte)'T', (byte)'I', (byte)'M' };
	final static byte [] TIM_SECRET = { (byte)'t', (byte)'i', (byte)'m',
		(byte)'s', (byte)'e', (byte)'c',(byte)'r', (byte)'e', (byte)'t' };
	
	//Keys of the TIM
	private final static byte[] timPrivExponent ={
		(byte)0x9d,(byte)0xd6,(byte)0xa5,(byte)0x87,(byte)0xf4,(byte)0x82,(byte)0x7a,(byte)0xd5,(byte)0x82,
		(byte)0x3c,(byte)0x8e,(byte)0x9f,(byte)0x1b,(byte)0x61,(byte)0x5f,(byte)0x61,(byte)0xe6,(byte)0x4a,
		(byte)0x1f,(byte)0x19,(byte)0x44,(byte)0xfb,(byte)0x6c,(byte)0xde,(byte)0xb0,(byte)0x86,(byte)0x1b,
		(byte)0xff,(byte)0x30,(byte)0x2c,(byte)0x89,(byte)0x4b,(byte)0xc7,(byte)0x75,(byte)0x95,(byte)0x1a,
		(byte)0x64,(byte)0x18,(byte)0x30,(byte)0x45,(byte)0x8b,(byte)0x6e,(byte)0x83,(byte)0x70,(byte)0x99,
		(byte)0xc3,(byte)0x41,(byte)0x39,(byte)0xbd,(byte)0xec,(byte)0x5a,(byte)0xa6,(byte)0x09,(byte)0xc8,
		(byte)0xd4,(byte)0x3e,(byte)0x57,(byte)0x36,(byte)0x55,(byte)0x15,(byte)0xcd,(byte)0x66,(byte)0xda,
		(byte)0x01};
	
	private final static byte[]  rsaPublicExponent ={(byte)0x01,(byte)0x00,(byte)0x01};
	
	private final static  byte[] timModulus ={
		(byte)0xbe,(byte)0xfe,(byte)0x94,(byte)0x39,(byte)0x4c,(byte)0x34,(byte)0xdc,(byte)0x57,(byte)0x69,
		(byte)0x6f,(byte)0x54,(byte)0x00,(byte)0x80,(byte)0x44,(byte)0x57,(byte)0xbe,(byte)0x61,(byte)0xc4,
		(byte)0x95,(byte)0x00,(byte)0xb3,(byte)0x2f,(byte)0x33,(byte)0x52,(byte)0xcc,(byte)0xd2,(byte)0x9b,
		(byte)0x5d,(byte)0x4e,(byte)0x7b,(byte)0x3e,(byte)0x0f,(byte)0x92,(byte)0x2a,(byte)0x88,(byte)0x08,
		(byte)0x62,(byte)0x02,(byte)0x33,(byte)0x87,(byte)0x76,(byte)0xd8,(byte)0xb7,(byte)0x84,(byte)0xef,
		(byte)0x6d,(byte)0x8d,(byte)0x9c,(byte)0x71,(byte)0x95,(byte)0x8a,(byte)0x0a,(byte)0x54,(byte)0x86,
		(byte)0xdd,(byte)0x7e,(byte)0x69,(byte)0x3d,(byte)0x83,(byte)0xb2,(byte)0xf9,(byte)0xee,(byte)0x8f,
		(byte)0xd3};
	
	private final static  byte[]  defaultTimAppKey_Modulus = {
	    (byte)0xcb, (byte)0xcd, (byte)0x0c, (byte)0x17, (byte)0xfb, (byte)0xad, (byte)0x17, (byte)0x6e, (byte)0xb0, (byte)0xa7, (byte)0xf5, (byte)0x05, (byte)0xca, (byte)0xc4, (byte)0x68,
	    (byte)0xd7, (byte)0xf4, (byte)0xe9, (byte)0x5d, (byte)0x9b, (byte)0x61, (byte)0x63, (byte)0x8a, (byte)0x78, (byte)0x8e, (byte)0x87, (byte)0x23, (byte)0xbf, (byte)0xcb, (byte)0x96,
	    (byte)0x6f, (byte)0x7f, (byte)0x01, (byte)0x8a, (byte)0x6f, (byte)0x5f, (byte)0xe1, (byte)0x90, (byte)0x3b, (byte)0x6f, (byte)0xfb, (byte)0x55, (byte)0x1e, (byte)0xe5, (byte)0x3e,
	    (byte)0x15, (byte)0xda, (byte)0xd4, (byte)0xee, (byte)0x8c, (byte)0x3a, (byte)0x37, (byte)0x75, (byte)0x4d, (byte)0x48, (byte)0x15, (byte)0xdd, (byte)0x8b, (byte)0xf9, (byte)0x3a,
	    (byte)0x26, (byte)0x2b, (byte)0xdb, (byte)0x93 };

	private final static  byte[]  defaultTimAppKey_privateExponent = {
	    (byte)0x56, (byte)0x6b, (byte)0x36, (byte)0x6b, (byte)0x9d, (byte)0x0f, (byte)0x02, (byte)0xd6, (byte)0xaf, (byte)0x16, (byte)0x29, (byte)0x72, (byte)0x31, (byte)0x4f, (byte)0x23,
	    (byte)0xde, (byte)0x1f, (byte)0x3e, (byte)0x2d, (byte)0xb1, (byte)0x4b, (byte)0x94, (byte)0xb8, (byte)0x0c, (byte)0xf2, (byte)0xf3, (byte)0x1f, (byte)0x17, (byte)0x9f, (byte)0x2e,
	    (byte)0xc5, (byte)0x4b, (byte)0xe5, (byte)0x99, (byte)0xc5, (byte)0xcb, (byte)0xa0, (byte)0xc1, (byte)0x52, (byte)0x9f, (byte)0x57, (byte)0xd2, (byte)0x9e, (byte)0x1b, (byte)0x3a,
	    (byte)0x8c, (byte)0x1d, (byte)0xfd, (byte)0x6b, (byte)0x59, (byte)0x54, (byte)0xa7, (byte)0xa6, (byte)0x7b, (byte)0xbc, (byte)0xb5, (byte)0xd5, (byte)0xf3, (byte)0x29, (byte)0x2f,
	    (byte)0xfc, (byte)0x8b, (byte)0x8b, (byte)0x61 };
    
	private final static  byte[] emptyTimAppKey_Value = {
	    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };

	// Crypto utils
	private RSAPrivateKey timPrivKey;
	private RSAPublicKey  timPubKey;
	private KeyPair    	  keyPair;
	private RSAPrivateKey appPrivKey;

	private Cipher cipherRsa;

	//list all applications and 
	private byte[] tempData;

	// temp buffer for request, tokens and keys
	private byte[] requestData;

	private byte[] tokenKeyData;
	private byte[] pubKey;
	private byte[] privKey;

	private byte[] dataToEncrypt;
	private byte[] dataEncrypted;
	
	short found_data_length = 0;
	short found_tokenKeyData_length = 0;
	short tokenKeyDataLength = 0;
	short requestDataLength = 0;

	short pubKeyLen         = 0;

	short timTokenLen       = 0;
	short timTokenSignLen   = 0;
	short dataToEncryptLength  = 0;
	short encryptedDataLength  = 0;
	
	
	//size of whole incomming data
	private short incomming;
	//size of received data
	private short received_data_length;
	//size of sent byte
	private short sent;
	//sequence number of the datagram
	private byte currentINS;
	//sequence number of the datagram
	private byte seq;
	
	//size of window for big data transfer
	private static final short window = (short) 120;
    
	// data storage
	RequestTokenRW request_token_key_data;
	
	private Tim() {
		tempData = new byte[(short)2048];
		// tempData[NUMBER_OF_TOKEN_OFFSET] = (byte)0x00;
		incomming = ZERO;
		received_data_length = ZERO;
		sent = ZERO;
		seq = 0;

		requestData       = new byte[(short)2048];
		pubKey            = new byte[(short)128];
		privKey           = new byte[(short)128];
		dataToEncrypt     = new byte[(short)2048];
		dataEncrypted     = new byte[(short)256];
		

		tokenKeyData = new byte[(short)2000];
		request_token_key_data = new RequestTokenRW((short)8192);
		
		// RSA
		//generating keys for the TIM
		cipherRsa    = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		appPrivKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
		timPrivKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
		timPrivKey.setExponent(timPrivExponent, ZERO, (short) timPrivExponent.length);
		timPrivKey.setModulus(timModulus, ZERO, (short) timModulus.length);
		
		timPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		timPubKey.setExponent(rsaPublicExponent, ZERO, (short) rsaPublicExponent.length);
		timPubKey.setModulus(timModulus, ZERO, (short) timModulus.length);
		
		try {
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
			
		} catch (Exception e) {
			// can not instantiate a 1024 key on emulator
			// or keypair on physical SIM card
		}
		
		register();
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new Tim();
	}

	public void process(APDU apdu) throws ISOException {
		// At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        /*

		// following lines don't work on physical SIM with on a physical phone
		 
		// check SELECT APDU command
		if ((buffer[ISO7816.OFFSET_CLA] == 0)
				&& (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)))
			return;
		// test class byte and channel
		if ((byte)(buffer[ISO7816.OFFSET_CLA] & 0xF0) != TIM_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		*/
		
		switch (buffer[ISO7816.OFFSET_INS]) {
		case STORE_DATA:
				switch (buffer[ISO7816.OFFSET_P1]) {
				case SET_APP_REQ:
					{
						//set a new request for a given App
						if(buffer[ISO7816.OFFSET_P2]==0) {
							// on each new request, reset "length" variables
							requestDataLength = 0;
							found_tokenKeyData_length = 0;
							tokenKeyDataLength = 0;
							found_data_length = 0;
						}
						short dataInBuffer = receiveData(buffer, dataLen, requestData);
						if (dataInBuffer == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						} else {
							requestDataLength = received_data_length;
						}
					}
					break;
				case SET_TOKENS:
				{
					//store tokens for a given App
					short dataInBuffer = receiveData(buffer, dataLen, tokenKeyData);
					if (dataInBuffer == -1) {
						// ISOException.throwIt(SW_WAITFOR_DATA);
					} else {
						tokenKeyDataLength = received_data_length;
						// if transfer finished, save request_token_key_data with empty app keys
						updateTokensAndKeys(emptyTimAppKey_Value, (short)emptyTimAppKey_Value.length, emptyTimAppKey_Value, (short)emptyTimAppKey_Value.length );
					}
				}
				break;
				case UPDATE_TOKENS:
				{
					// update tokens for a given App, do not overwrite tim app keys
					short dataInBuffer = receiveData(buffer, dataLen, tokenKeyData);
					if (dataInBuffer == -1) {
						// ISOException.throwIt(SW_WAITFOR_DATA);
					} else {
						tokenKeyDataLength = received_data_length;

						short offset = request_token_key_data.searchRequestData(requestData);
						if(offset==-1) {
							ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						}

						request_token_key_data.getTokensAndAppKeys(offset, tempData, ZERO);
						
						// get previous keys
						offset = RequestTokenRW.skipParam(tempData, THREE, ZERO);
						pubKeyLen = Util.getShort(tempData,offset);
						offset += TWO;
						Util.arrayCopy(tempData, offset, pubKey, ZERO, pubKeyLen);
						offset += pubKeyLen;
						short privKeyLen = Util.getShort(tempData,offset);
						offset += TWO;
						Util.arrayCopy(tempData, offset, privKey, ZERO, privKeyLen);

						// set new tokens only
						updateTokensAndKeys(pubKey, pubKeyLen, privKey, privKeyLen );
					}
				}
				break;
				case SET_USERINFO:
					//store userinfo
					break;
				case DELETE_TOKENS_KEY:
				{
					if( request_token_key_data.removeRequestData(requestData) == false ) {
						ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
					}
				}
				break;
				case SET_RESET:
				{
					request_token_key_data.reset();
				}
				break;
				case SET_ENCRYPT_DATA:
				{
					// store data to be signed
					short dataInBuffer = receiveData(buffer, dataLen, dataToEncrypt);
					if (dataInBuffer == -1) {
						// ISOException.throwIt(SW_WAITFOR_DATA);
						dataToEncryptLength = 0;
						encryptedDataLength = 0;
					} else {
						dataToEncryptLength = received_data_length;
					}
				}
				break;
				default:
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
			break;
		case GET_DATA:
				switch (buffer[ISO7816.OFFSET_P1]) {
				case GET_TIM_ID:
					{
						//get TIM ID
						short dataSent = sendData(TIM_ID, ZERO, (short)TIM_ID.length, buffer, apdu);
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					}
					break;
				case GET_TIM_SECRET:
					{
						//get TIM SECRET
						short dataSent = sendData(TIM_SECRET, ZERO, (short)TIM_SECRET.length, buffer, apdu);
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					}
					break;
				case GET_REFRESH_TOKEN_WITH_TIM_APP_KEY:
					//get the TIM authentication token
					/*
					short dataSent = sendData(tempData, ZERO,(short)100 , buffer, arg0);
					if (dataSent == -1) {
						ISOException.throwIt(SW_WAITFOR_DATA);
					}
					*/
					
					break;
				case SEARCH_TOKENS:
					// find request
					{
						short offset = request_token_key_data.searchRequestData(requestData);
						found_tokenKeyData_length = 0;
						if(offset!=-1) {
							found_tokenKeyData_length = request_token_key_data.getTokensAndPubKey(offset, tokenKeyData, ZERO);
							tokenKeyDataLength = found_tokenKeyData_length;
						} else {
							ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						}
					}
					break;
				case GET_TK_ALL:
					sendData(tokenKeyData, ZERO, (short)tokenKeyData.length , buffer, apdu);
					break;
				case GET_APP_REQ:
					sendData(requestData, ZERO, (short)requestData.length , buffer, apdu);
					break;
				case GET_TOKENS_KEY:
					{
						if(found_tokenKeyData_length>0) {
							short dataSent = sendData(tokenKeyData, ZERO, found_tokenKeyData_length , buffer, apdu);
						
							if (dataSent == -1) {
								// ISOException.throwIt(SW_WAITFOR_DATA);
							}
						} else {
							ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						}
					}
					break;
				case GET_TOKENS:
				{
					// find request
					if(buffer[ISO7816.OFFSET_P2]==0) {
						short offset = request_token_key_data.searchRequestData(requestData);
						found_tokenKeyData_length = 0;
						if(offset!=-1) {
							found_tokenKeyData_length = request_token_key_data.getTokens(offset, tokenKeyData, ZERO);
						} else {
							ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						}
					}

					if(found_tokenKeyData_length>0) {
						short dataSent = sendData(tokenKeyData, ZERO, found_tokenKeyData_length , buffer, apdu);
					
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					} else {
						ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
					}
				}
				break;
				case GET_ACCESS_TOKEN:
					//get an access token
					break;
				case GET_USER_INFO:
					//get userinfo
					break;
				case GET_FREE_SPACE:
					//get free space
					Util.setShort(buffer, ZERO, request_token_key_data.getFreeSpace());
					apdu.setOutgoing();
					apdu.setOutgoingLength(TWO);
					apdu.sendBytesLong(buffer, ZERO, TWO);
					break;
				case GET_PUB_KEY:
					{
						short dataSent = sendData(pubKey, ZERO, pubKeyLen , buffer, apdu);
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					}
					break;
				case GET_ALL:
				{
					short dataSent = sendData(request_token_key_data.tr_buffer, ZERO, (short)request_token_key_data.tr_buffer.length , buffer, apdu);
					if (dataSent == -1) {
						// ISOException.throwIt(SW_WAITFOR_DATA);
					}
				}
				break;
				case GET_ENCRYPTED_TIM:
				{
					// compute signature on first block
					if(buffer[ISO7816.OFFSET_P2]==0) {
						encryptedDataLength = 0;
						// check data
						if(dataToEncryptLength<=0) {
							ISOException.throwIt(ISO7816.SW_DATA_INVALID);
						}
						// encrypt
						cipherRsa.init(timPrivKey, Cipher.MODE_ENCRYPT);
						encryptedDataLength = cipherRsa.doFinal(dataToEncrypt, ZERO, dataToEncryptLength, dataEncrypted, ZERO);
					}

					if( encryptedDataLength > 0 ) {
						short dataSent = sendData(dataEncrypted, ZERO, encryptedDataLength , buffer, apdu);
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					} else {
						ISOException.throwIt(ISO7816.SW_DATA_INVALID);
					}
				}
				break;
				case GET_ENCRYPTED_TAK:
				{
					// compute signature on first block
					if(buffer[ISO7816.OFFSET_P2]==0) {
						encryptedDataLength = 0;
						computePrivateTokenCrypt();
					}
					if( encryptedDataLength > 0 ) {
						short dataSent = sendData(dataEncrypted, ZERO, encryptedDataLength , buffer, apdu);
						if (dataSent == -1) {
							// ISOException.throwIt(SW_WAITFOR_DATA);
						}
					} else {
						ISOException.throwIt(ISO7816.SW_DATA_INVALID);
					}
				}
				break;
				case GET_VERSION:
					//get free space
					buffer[ZERO] = TIM_SIM_VERSION;
					apdu.setOutgoing();
					apdu.setOutgoingLength(ONE);
					apdu.sendBytesLong(buffer, ZERO, ONE);
				break;
				default:
					ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				}
			break;
		case CHECK_AR:

			break;
		case AUTH_USER:

			break;
		case MAKE_DATA:
			{
				switch (buffer[ISO7816.OFFSET_P1]) {
				case GEN_TIM_APP_KEY:
					// find request
					if(buffer[ISO7816.OFFSET_P2]==0) {

						// should be called by a previous search
						if(found_tokenKeyData_length>0) {

							// init key length
							pubKeyLen = 0;
							short privKeyLen = 0;
							
							// generate new key pair if possible
							if(keyPair!=null) {
								try {
									keyPair.genKeyPair();
									RSAPublicKey  rsaPubKey  = (RSAPublicKey)  keyPair.getPublic();
									RSAPrivateKey rsaPrivKey = (RSAPrivateKey) keyPair.getPrivate();
									pubKeyLen  = rsaPubKey.getModulus(  pubKey,  ZERO);
									privKeyLen = rsaPrivKey.getExponent(privKey, ZERO);
								} catch (Exception e) {
								}
							}
							
							// set to default if generation failed
							if( pubKeyLen==0 || privKeyLen == 0 ) {
								pubKeyLen  = (short)defaultTimAppKey_Modulus.length;
								Util.arrayCopy(defaultTimAppKey_Modulus,         ZERO, pubKey,  ZERO, pubKeyLen);
								privKeyLen = (short)defaultTimAppKey_privateExponent.length;
								Util.arrayCopy(defaultTimAppKey_privateExponent, ZERO, privKey, ZERO, privKeyLen);
							}

							// set new data
							updateTokensAndKeys(pubKey, pubKeyLen, privKey, privKeyLen );
	
						} else {
							ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
						}
					} else {
						ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
					}
					break;
				}
			}
			break;

		default:
			// ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/*
	 * Method to receive more data
	 */
	private short receiveData(byte[] buffer, short dataLen, byte[] dest) {
		
		if (buffer[ISO7816.OFFSET_P2] == 0x00) {
			currentINS = buffer[ISO7816.OFFSET_P1];
			seq = buffer[ISO7816.OFFSET_P2];
			received_data_length = 0;
			incomming = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
			if ( incomming > dest.length ) {
				ISOException.throwIt(ISO7816.SW_FILE_FULL);
			}
			received_data_length += (short) (dataLen - TWO);
			Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + TWO), dest, ZERO, received_data_length);
		} else if (buffer[ISO7816.OFFSET_P2] == (short)(seq + 1)){
			Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA), dest, received_data_length, dataLen);
			received_data_length += dataLen;
			seq++;
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		if ((short)(incomming - received_data_length) > 0) {
			return -1;
		} else {
			return incomming;
		}
	}
	/*
	 * Method to send more data
	 */
	private short sendData(byte[] outbuffer,short offset, short dataLen, byte[] apduBuffer, APDU apdu) {
		if (apduBuffer[ISO7816.OFFSET_P2] == 0x00) {
			currentINS = apduBuffer[ISO7816.OFFSET_P1];
			seq = apduBuffer[ISO7816.OFFSET_P2];
			if(seq<0) {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			sent = 0;
			if ((short)(dataLen+TWO) <= window) {
				Util.setShort(apduBuffer, ZERO, dataLen);
				Util.arrayCopy(outbuffer, offset, apduBuffer, TWO, dataLen);
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)(dataLen+TWO));
				apdu.sendBytesLong(apduBuffer, ZERO, (short)(dataLen+TWO));
				sent += dataLen;
			} else {
				Util.setShort(apduBuffer, ZERO, dataLen);
				Util.arrayCopy(outbuffer, offset, apduBuffer, TWO, (short)(window-TWO));
				apdu.setOutgoing();
				apdu.setOutgoingLength(window);
				apdu.sendBytesLong(apduBuffer, ZERO, window);
				sent += (short)(window-TWO);
			}
		} else if (apduBuffer[ISO7816.OFFSET_P2] == (short)(seq + 1)){
			if ((short) (dataLen-sent) <= window) {	
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) (dataLen-sent));
				apdu.sendBytesLong(outbuffer, sent,(short) (dataLen-sent));
				sent += (short) (dataLen-sent);
			} else {
				apdu.setOutgoing();
				apdu.setOutgoingLength(window);
				apdu.sendBytesLong(outbuffer, sent, window);
				sent += window;
			}
			seq++;
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		if ((short)(dataLen - sent) > 0) {
			return -1;
		} else {
			return sent;
		}
	}

	// compute encrypted value according to current request param private key
	void computePrivateTokenCrypt() {

		// check data
		if(dataToEncryptLength<=0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		// find request
		short offset = request_token_key_data.searchRequestData(requestData);
		found_data_length = 0;
		if(offset>2) {
			found_data_length = request_token_key_data.getTokensAndAppKeys(offset, tokenKeyData, ZERO);
		} else {
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}

		try {
			// find key
			offset = RequestTokenRW.skipParam(tokenKeyData, THREE, ZERO);
			short keySize = Util.getShort(tokenKeyData, offset);
			offset += TWO;
			// build key
			appPrivKey.setModulus(tokenKeyData, offset, keySize);
			offset += keySize;
			keySize = Util.getShort(tokenKeyData, offset);
			offset += TWO;
			appPrivKey.setExponent(tokenKeyData, offset, keySize);
			
			// sign data
			cipherRsa.init(appPrivKey, Cipher.MODE_ENCRYPT);
			encryptedDataLength = cipherRsa.doFinal(dataToEncrypt, ZERO, dataToEncryptLength, dataEncrypted, ZERO);

		} catch (Exception e) {
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		}
	}

	// update keys for current request param
	boolean updateTokensAndKeys( byte pub_key[], short pub_key_len, byte priv_key[], short priv_key_len ) {

		if( tokenKeyDataLength <= 0 ) {
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		// update new tokens with specified keys
		short offsetUpdate = RequestTokenRW.skipParam(tokenKeyData, THREE, ZERO);
		offsetUpdate = Util.setShort(tokenKeyData, offsetUpdate, pub_key_len);
		offsetUpdate = Util.arrayCopy(pub_key,  ZERO, tokenKeyData, offsetUpdate, pub_key_len);

		found_tokenKeyData_length = offsetUpdate;

		offsetUpdate = Util.setShort(tokenKeyData, offsetUpdate, priv_key_len);
		offsetUpdate = Util.arrayCopy(priv_key, ZERO, tokenKeyData, offsetUpdate, priv_key_len);
		

		// if transfer finished, update request_token_key_data with previous keys
		if( request_token_key_data.setRequestToken(requestData, tokenKeyData) == false ) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
		
		found_tokenKeyData_length = 0;
		tokenKeyDataLength = 0;
		return true;
	}
}
