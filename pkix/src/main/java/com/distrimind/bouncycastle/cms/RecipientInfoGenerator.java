package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.asn1.cms.RecipientInfo;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
