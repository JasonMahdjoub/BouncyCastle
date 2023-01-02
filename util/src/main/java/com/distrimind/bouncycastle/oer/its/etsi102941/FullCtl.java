package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;
import com.distrimind.bouncycastle.asn1.ASN1Boolean;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;
import com.distrimind.bouncycastle.oer.its.etsi102941.basetypes.Version;

public class FullCtl
    extends CtlFormat
{

    public FullCtl(Version version, Time32 nextUpdate, ASN1Boolean isFullCtl, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        super(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
    }

    protected FullCtl(ASN1Sequence seq)
    {
        super(seq);
    }

    public static FullCtl getInstance(Object o)
    {
        if (o instanceof FullCtl)
        {
            return (FullCtl)o;
        }

        if (o != null)
        {
            return new FullCtl(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
