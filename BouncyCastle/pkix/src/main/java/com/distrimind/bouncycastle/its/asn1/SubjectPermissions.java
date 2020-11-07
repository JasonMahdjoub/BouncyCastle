package com.distrimind.bouncycastle.its.asn1;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     SubjectPermissions ::= CHOICE {
 *         explicit SequenceOfPsidSspRange,
 *         all NULL,
 *         ...
 *     }
 * </pre>
 */
public class SubjectPermissions
    extends ASN1Object
    implements ASN1Choice
{
    public static SubjectPermissions getInstance(Object src)
    {
        if (src instanceof SubjectPermissions)
        {
            return (SubjectPermissions)src;
        }
        else if (src != null)
        {
            // TODO: ....
            return null;
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
