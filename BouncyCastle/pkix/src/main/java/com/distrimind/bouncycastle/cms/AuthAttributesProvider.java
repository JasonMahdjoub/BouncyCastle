package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
