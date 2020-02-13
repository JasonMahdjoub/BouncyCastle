package org.bouncycastle.bcasn1.tsp;

import org.bouncycastle.bcasn1.ASN1EncodableVector;
import org.bouncycastle.bcasn1.ASN1Object;
import org.bouncycastle.bcasn1.ASN1OctetString;
import org.bouncycastle.bcasn1.ASN1Primitive;
import org.bouncycastle.bcasn1.ASN1Sequence;
import org.bouncycastle.bcasn1.DEROctetString;
import org.bouncycastle.bcasn1.DERSequence;
import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bcutil.Arrays;

public class MessageImprint
    extends ASN1Object
{
    AlgorithmIdentifier hashAlgorithm;
    byte[]              hashedMessage;
    
    /**
     * @param o
     * @return a MessageImprint object.
     */
    public static MessageImprint getInstance(Object o)
    {
        if (o instanceof MessageImprint)
        {
            return (MessageImprint)o;
        }

        if (o != null)
        {
            return new MessageImprint(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    private MessageImprint(
        ASN1Sequence seq)
    {
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.hashedMessage = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }
    
    public MessageImprint(
        AlgorithmIdentifier hashAlgorithm,
        byte[]              hashedMessage)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.hashedMessage = Arrays.clone(hashedMessage);
    }
    
    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    public byte[] getHashedMessage()
    {
        return Arrays.clone(hashedMessage);
    }
    
    /**
     * <pre>
     *    MessageImprint ::= SEQUENCE  {
     *       hashAlgorithm                AlgorithmIdentifier,
     *       hashedMessage                OCTET STRING  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(hashAlgorithm);
        v.add(new DEROctetString(hashedMessage));

        return new DERSequence(v);
    }
}