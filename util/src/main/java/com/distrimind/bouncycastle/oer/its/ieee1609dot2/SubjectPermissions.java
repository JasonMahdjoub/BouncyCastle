package com.distrimind.bouncycastle.oer.its.ieee1609dot2;

import com.distrimind.bouncycastle.asn1.ASN1Choice;
import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1Null;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.ASN1TaggedObject;
import com.distrimind.bouncycastle.asn1.BERTags;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.DERTaggedObject;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSspRange;


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

    public static final int explicit = 0;
    public static final int all = 1;

    private final ASN1Encodable subjectPermissions;
    private final int choice;

    SubjectPermissions(int choice, ASN1Encodable value)
    {
        this.subjectPermissions = value;
        this.choice = choice;
    }

    public static SubjectPermissions explicit(SequenceOfPsidSspRange range)
    {
        return new SubjectPermissions(explicit, range);
    }

    public static SubjectPermissions all()
    {
        return new SubjectPermissions(all, DERNull.INSTANCE);
    }



    private SubjectPermissions(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();

        switch (choice)
        {
        case explicit:
            subjectPermissions = SequenceOfPsidSspRange.getInstance(ato.getExplicitBaseObject());
            break;
        case all:
            subjectPermissions = ASN1Null.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }


    public static SubjectPermissions getInstance(Object src)
    {
        if (src instanceof SubjectPermissions)
        {
            return (SubjectPermissions)src;
        }

        if (src != null)
        {
            return new SubjectPermissions(ASN1TaggedObject.getInstance(src, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public ASN1Encodable getSubjectPermissions()
    {
        return subjectPermissions;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, subjectPermissions);
    }



}
