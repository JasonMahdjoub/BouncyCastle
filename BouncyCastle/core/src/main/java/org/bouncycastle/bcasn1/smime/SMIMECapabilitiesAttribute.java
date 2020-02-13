package org.bouncycastle.bcasn1.smime;

import org.bouncycastle.bcasn1.DERSequence;
import org.bouncycastle.bcasn1.DERSet;
import org.bouncycastle.bcasn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}
