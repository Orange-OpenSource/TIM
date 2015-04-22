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


/**
 * base64url encoding.
 * @param  String $input    Data to be encoded. 
 * @param  Int    $nopad    Whether "=" pad the output or not. 
 * @param  Int    $wrap     Whether to wrap the result. 
 * @return base64url encoded $input. 
 */
function base64url_encode($input,$nopad=1,$wrap=0)
{
    $data  = base64_encode($input);

    if($nopad) {
	$data = str_replace("=","",$data);
    }
    $data = strtr($data, '+/=', '-_,');
    if ($wrap) {
        $datalb = ""; 
        while (strlen($data) > 64) { 
            $datalb .= substr($data, 0, 64) . "\n"; 
            $data = substr($data,64); 
        } 
        $datalb .= $data; 
        return $datalb; 
    } else {
        return $data;
    }
}

/**
 * base64url encoding.
 * @param  String $input    Data to be Base64url decoded.
 * @return Decoded data
 */
function base64url_decode($input)
{
    return base64_decode(strtr($input, '-_,', '+/='));
}
?>
