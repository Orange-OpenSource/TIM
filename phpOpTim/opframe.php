<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("abconstants.php");
require_once("libjsoncrypto.php");
require_once('libdb.php');

error_reporting(E_ERROR | E_WARNING | E_PARSE);

header('Content-Type: text/html; charset=utf-8');


?>

<html>
<head>
<meta http-equiv="content-type" content="text/html;charset=UTF-8" />
<title>OP Frame</title>
<script src="http://crypto-js.googlecode.com/svn/tags/3.0.2/build/rollups/sha256.js"></script>
<script type='text/javascript'>//<![CDATA[

/*
 *
 * Server Side API
 *
 */



window.addEventListener("message",receiveMessage, false);

function getCookie(c_name)
{
    var i,x,y,ARRcookies=document.cookie.split(";");
    for (i=0;i<ARRcookies.length;i++)
    {
        x=ARRcookies[i].substr(0,ARRcookies[i].indexOf("="));
        y=ARRcookies[i].substr(ARRcookies[i].indexOf("=")+1);
        x=x.replace(/^\s+|\s+$/g,"");
        if (x==c_name)
        {
            return unescape(y);
        }
  }
}

function printCookies()
{
    console.log('cookies : <-----');
    var i,x,y,ARRcookies=document.cookie.split(";");
    console.log('cookies = ' + document.cookie);
    for (i=0;i<ARRcookies.length;i++)
    {
        console.log("cookie[" + i + "] = " + ARRcookies[i]); 
        x=ARRcookies[i].substr(0,ARRcookies[i].indexOf("="));
        y=ARRcookies[i].substr(ARRcookies[i].indexOf("=")+1);
        x=x.replace(/^\s+|\s+$/g,"");
        console.log('C["' + x + '"] = ' + y);
  }
  console.log('cookies : ----->');
}


function receiveMessage(e){
  console.log("opframe receive message")
//  if ( e.origin !== origin) {
//    console.log(e.origin + ' !== ' + origin);
//    alert("different origin " + origin + " != " + e.origin)
//    return;
//  }
  var state = '';
  console.log('opFrame data = ' + e.data);

  
  var parts = e.data.split(' ');
  var client_id = parts[0];
  var session_state = parts[1];
  var ss_parts = session_state.split('.');
  var salt = ss_parts[1];

  var ops = getCookie('ops');



  console.log('client_id : ' + client_id + ' origin : ' + e.origin + ' opss : ' + ops + ' salt : ' + salt);
  console.log('opmes crypto input = ' + client_id + e.origin + ops + salt + "." + salt);
  var ss = CryptoJS.SHA256(client_id + e.origin + ops + salt) + "." + salt;
  console.log('calculated ss  = ' + ss);
  if (session_state == ss) {
    state = 'unchanged';
  } else {
    console.log('received:' + session_state + ' != ' + ss);
    state = 'changed';
  }
    console.log('opfram posting : ' + state);
  e.source.postMessage(state, e.origin);
};

function supports_html5_storage() {
  try {
    return 'localStorage' in window && window['localStorage'] !== null;
  } catch (e) {
    return false;
  }
}




//]]></script>
</head>
<body>
</body>
</html>
