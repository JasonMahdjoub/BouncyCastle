package org.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
