package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;
}
