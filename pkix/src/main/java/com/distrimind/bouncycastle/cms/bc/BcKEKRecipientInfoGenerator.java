package com.distrimind.bouncycastle.cms.bc;

import com.distrimind.bouncycastle.cms.KEKRecipientInfoGenerator;
import com.distrimind.bouncycastle.operator.bc.BcSymmetricKeyWrapper;
import com.distrimind.bouncycastle.asn1.cms.KEKIdentifier;

public class BcKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        super(kekIdentifier, kekWrapper);
    }

    public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper);
    }
}
