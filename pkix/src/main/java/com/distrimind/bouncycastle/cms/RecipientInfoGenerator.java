package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.cms.RecipientInfo;
import com.distrimind.bouncycastle.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
