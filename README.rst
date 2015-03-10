==========================
Trusted Identity Module
==========================

A local smartphone module acting as an OpenID Connect Server proxy and delivers trusted tokens to installed native applications. The TIM improves the user experience with single sign on, security and privacy enhancement.

Description
-----------
The Trusted Identity Module project is a set of four projects:  an Android service, a JAVA Card Service, a modified OpenID Connect Server (with TIM features)
and a basic Android TIM-Client app enabling to test the TIM services. The OIDC-TIM server is based on an `open source implementation of OpenID Connect in PHP by Nomura Research Institute, Ltd`_.

The TIM (Android and JavaCard parts) operates as a server and receives requests from native applications needing to access user personnal data.
The TIM works in offline and online modes and provides many benefits among with:

*	Usage continuity when in offline scenario (or in a roaming situation)
*	Privacy improvement for the end-user as the online IdP is not contacted and therefore unable to track the user’s activity
*	Improved security with the use of a combination of Trusted Execution and Secure storage
    
In online mode the TIM is connected to the OIDC-TIM server and recovers access tokens and refresh tokens for the requesting app.
The TIM then stores the tokens in the JAVA Card. Based on those tokens the TIM creates new access tokens (tim-access tokens) for the requesting application which
can then use it to access a Ressource Server and recover requested user personnal data. 

In the offline mode, the TIM does not contact the OIDC-TIM server but instead uses the stored tokens to create tim-access tokens for
native applications. The offline mode prevents the server from monitoring the user activity and hence preserves his privacy.
The security is enhanced by the smart card, with the secure storage. The TIM is not dependent of a particular network access technology and 
ensures the usage continuity when moving from a technology to another (eg: wifi to 4G).

.. _`open source implementation of OpenID Connect in PHP by Nomura Research Institute, Ltd`: https://bitbucket.org/PEOFIAMP/phpoidc/


References
----------
* OpenID Connect protocol http://openid.net/connect/
* `OpenID Connect Server Implementation (PHP)`_ (phpOIDC Project, commit number 6ac8e6d from 2014-09-05)
* Smart Card API for Android `Seek For Android`_ 
* Cryptography Libraries for Android `Spongy castle libs from Roberto Tyley`_

   
.. _`Seek For Android`: https://code.google.com/p/seek-for-android/wiki/Index
.. _`OpenID Connect Server Implementation (PHP)`: https://bitbucket.org/PEOFIAMP/phpoidc/
.. _`Spongy castle libs from Roberto Tyley`: https://github.com/rtyley/spongycastle



Development Tools
-----------------
* SIM Development: `IzyNFC`_
* Android Development: `Eclipse`_ + `Android ADT plugin`_
* Server Development: Any PHP Server, `Easy PHP`_ is a good one

.. _`IzyNFC`: http://izynfc.sourceforge.net/
.. _`Eclipse`: https://eclipse.org/downloads/
.. _`Android ADT plugin`: http://developer.android.com/tools/sdk/eclipse-adt.html
.. _`Easy PHP`: http://www.easyphp.org/
Required Equipment
-------------------
* For JAVA Card development: a JAVA Card at least version 2.2.1 with a Card Reader
* For Android development: a `compatible android device`_

.. _`compatible android device`: https://code.google.com/p/seek-for-android/wiki/Devices


Installation
------------
After downloading and setting up the development environments, download every part of the project (OIDC-TIM Server, Android service, JAVA Card service, and the test app)

Import the projects in the corresponding environments, for example: the Android Service and the test app in Eclipse + ADT, the JAVA Card service in IzyNfc.
For the OIDC-TIM server, follow the steps described in `the phpOIDC project`_ and then replace the corresponding files with the OIDC-TIM project files.

Compile and execute on the corresponding devices (JAVACard and Android devices).
  
.. _`the phpOIDC project`: https://bitbucket.org/PEOFIAMP/phpoidc/


TIM Sequence Diagram
====================

.. image:: https://cloud.githubusercontent.com/assets/11352074/6554851/3382fa6a-c660-11e4-9db9-5f2497b8e40a.png


Authorization request
=====================
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554846/33599436-c660-11e4-811f-2dc0b455bb20.png

Refresh Token Request
=====================
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554848/337ed318-c660-11e4-91ca-99e420ef84ba.png

New TIM Access Token Request
============================
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554850/3382399a-c660-11e4-9ac3-de3bf5da406a.png


User Infos Request
============================
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554847/336d638a-c660-11e4-88bf-88d059b0a76f.png


User Infos Request
==================
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554847/336d638a-c660-11e4-88bf-88d059b0a76f.png

Use Case 01
===========
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554852/338330ac-c660-11e4-9a3a-4f89ed0ec62d.png

Use Case 02
===========
.. image:: https://cloud.githubusercontent.com/assets/11352074/6554849/338016c4-c660-11e4-9014-bcfcca67aa3f.png


License
-------

Copyright © 2015 Orange

This project is licensed under the Apache License, Version 2.0 (the "License");
you may not use it except in compliance with the License.
You may obtain a copy of the License at

&nbsp;&nbsp;&nbsp;http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
