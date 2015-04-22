#!/bin/sh

channel_exists()
{
    CHANNEL=$1

    pear list-channels | grep -q "$CHANNEL"
    if [ $? -eq 0 ]; then
#       echo "channel $CHANNEL exists"
        return 1
    else
#       echo "channel $CHANNEL DOES NOT exist"
       return 0
    fi
}

channel_add()
{
    CHANNEL=$1

    channel_exists $CHANNEL
    if [ $? -eq 0 ]; then
        pear channel-discover "$CHANNEL"
    fi

}

package_exists()
{
    CHANNEL=$1
    PACKAGE=$2

    pear list -c "$CHANNEL" | grep -q "^$PACKAGE[[:space:]]*.*[[:space:]]*.*$"
    if [ $? -eq 0 ]; then
#       echo "package $CHANNEL/$PACKAGE exists"
       return 1
    else
#        echo "package $CHANNEL/$PACKAGE DOES NOT exist"
        return 0
    fi
}

channel_package_exists()
{
    CHANNEL=$1
    PACKAGE=$2

    channel_exists $CHANNEL
    if [ $? -eq 1 ]; then
        pear list -c "$CHANNEL" | grep -q "^$PACKAGE[[:space:]]*.*[[:space:]]*.*$"
        if [ $? -eq 0 ]; then
#            echo "$CHANNEL/$PACKAGE exists"
            return 1
        else
#            echo "$CHANNEL/$PACKAGE DOES NOT exist"
            return 0
        fi
    else
#        echo "$CHANNEL/$PACKAGE DOES NOT exist"
        return 0
    fi
}

package_add()
{
    CHANNEL=$1
    shift

    channel_add $CHANNEL

    for PACKAGE in $@
    do
        package_exists $CHANNEL $PACKAGE
        if [ $? -eq 0 ]; then
#            echo "installing $CHANNEL/$PACKAGE"
            pear install $CHANNEL/$PACKAGE
        fi
    done
}

package_delete()
{
    CHANNEL=$1
    shift

    channel_exists $CHANNEL
    if [ $? -eq 1 ]; then
        for PACKAGE in $@
        do
            package_exists $CHANNEL $PACKAGE
            if [ $? -eq 1 ]; then
                echo "uninstalling $CHANNEL/$PACKAGE"
                pear uninstall $CHANNEL/$PACKAGE
            fi
        done
    fi
}


# Crypt_AES       0.3.5   stable
# Crypt_DES       0.3.5   stable
# Crypt_Hash      0.3.5   stable
# Crypt_RC4       0.3.5   stable
# Crypt_RSA       0.3.5   stable
# Crypt_Random    0.3.5   stable
# Crypt_Rijndael  0.3.5   stable
# Crypt_TripleDES 0.3.5   stable
# File_ANSI       0.3.5   stable
# File_ASN1       0.3.5   stable
# File_X509       0.3.5   stable
# Math_BigInteger 0.3.5   stable

# package_delete "phpseclib.sourceforge.net" Crypt_RSA Crypt_Random Crypt_AES Crypt_RC4 Crypt_Rijndael Crypt_TripleDES File_ANSI File_X509 Crypt_DES Crypt_Hash Math_BigInteger File_ASN1

# package_delete pear.doctrine-project.org Doctrine
package_add "pear.php.net" MDB2 MDB2_Driver_mysql

package_add "phpseclib.sourceforge.net"  Math_BigInteger Crypt_AES Crypt_DES Crypt_Hash Crypt_RC4  Crypt_TripleDES Crypt_RSA Crypt_Random Crypt_Rijndael File_ANSI File_ASN1 File_X509

package_add "pear.doctrine-project.org" Doctrine

