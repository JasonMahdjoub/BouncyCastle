package com.distrimind.bouncycastle.internal.asn1.misc;

import com.distrimind.bouncycastle.asn1.ASN1IA5String;
import com.distrimind.bouncycastle.asn1.DERIA5String;

public class VerisignCzagExtension
    extends DERIA5String
{
    public VerisignCzagExtension(
        ASN1IA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "VerisignCzagExtension: " + this.getString();
    }
}
