==========================
Trusted Identity Module
==========================

A local smartphone module acting as an OpenID Connect Server proxy and obtains tokens on behalf of installed native applications. The TIM improves the user experience with single sign on, security and privacy enhancement.

Description
-----------
This repository contains four modules that are complementary. We have on one hand services that are part of the Trusted Identity Module (an Android service and a JAVA Card Service), and a modified OpenID Connect Server (with TIM features). On the other hand, a basic Android client app enabling to test the TIM services.
The OIDC-TIM server is based on an `open source implementation of OpenID Connect in PHP by Nomura Research Institute, Ltd`_.

.. _`open source implementation of OpenID Connect in PHP by Nomura Research Institute, Ltd`: https://bitbucket.org/PEOFIAMP/phpoidc/


References
----------
   * OpenID Connect protocol http://openid.net/connect/
   * `OpenID Connect Server Implementation (PHP)`_ (commit number 6ac8e6d from 2014-09-05)
   * Smart Card API for Android `Seek For Android`_ 
   * Cryptography Libraries for Android `Spongy castle libs from Roberto Tyley`_

   
.. _`Seek For Android`: https://code.google.com/p/seek-for-android/wiki/Index
.. _`OpenID Connect Server Implementation (PHP)`: https://bitbucket.org/PEOFIAMP/phpoidc/
.. _`Spongy castle libs from Roberto Tyley`: https://github.com/rtyley/spongycastle


Development Tools
-----------------
   * SIM Development: `IzyNFC`_
   * Android Development: `Eclipse`_ + `Android ADT plugin`_
   * Server Development: Any PHP Editor and Server `Easy PHP`_

.. _` IzyNFC`: http://izynfc.sourceforge.net/
.. _`Eclipse`: https://eclipse.org/downloads/
.. _`Android ADT plugin`: http://developer.android.com/tools/sdk/eclipse-adt.html
.. _`Android Studio`: http://developer.android.com/tools/studio/index.html
Required Equipment
-------------------
   * For JAVA Card development: a JAVA Card at least version 2.2.1 with a Card Reader
   * For Android development: a `compatible android device`_

.. _`compatible android device`:
https://code.google.com/p/seek-for-android/wiki/Devices


Installation
------------
After downloading and setting up the development environments, download every part of the project (OIDC-TIM Server, Android service, JAVA Card service, and the test app)

Import the projects in the corresponding environments, for example: the Android Service and the test app in Eclipse + ADT, the JAVA Card service in IzyNfc.
For the OIDC-TIM server, follow the steps described in `the phpOIDC project`_ and then replace the corresponding files with the OIDC-TIM files.

Compile and execute on the corresponding devices (JAVACard and Android ).
  
.. _`the phpOIDC project`:
https://bitbucket.org/PEOFIAMP/phpoidc/


TIM Sequence Diagram
====================

.. image:: https://cloud.githubusercontent.com/assets/11352074/6554851/3382fa6a-c660-11e4-9db9-5f2497b8e40a.png


Authorization request
=====================
![](https://cloud.githubusercontent.com/assets/11352074/6554846/33599436-c660-11e4-811f-2dc0b455bb20.png)

Refresh Token Request
=====================
![](https://cloud.githubusercontent.com/assets/11352074/6554848/337ed318-c660-11e4-91ca-99e420ef84ba.png)

New TIM Access Token Request
============================
![](https://cloud.githubusercontent.com/assets/11352074/6554850/3382399a-c660-11e4-9ac3-de3bf5da406a.png)


User Infos Request
============================
![](https://cloud.githubusercontent.com/assets/11352074/6554847/336d638a-c660-11e4-88bf-88d059b0a76f.png)


User Infos Request
==================
![](https://cloud.githubusercontent.com/assets/11352074/6554847/336d638a-c660-11e4-88bf-88d059b0a76f.png)

Use Case 01
===========
![](https://cloud.githubusercontent.com/assets/11352074/6554852/338330ac-c660-11e4-9a3a-4f89ed0ec62d.png)

Use Case 02
===========
![](https://cloud.githubusercontent.com/assets/11352074/6554849/338016c4-c660-11e4-9014-bcfcca67aa3f.png)


License
-------


Copyright © 2015[Orange Labs]
