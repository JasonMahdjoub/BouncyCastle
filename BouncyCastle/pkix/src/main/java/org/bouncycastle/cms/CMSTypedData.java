package org.bouncycastle.cms;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
