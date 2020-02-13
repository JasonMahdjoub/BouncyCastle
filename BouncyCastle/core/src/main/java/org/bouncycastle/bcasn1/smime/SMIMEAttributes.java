package org.bouncycastle.bcasn1.smime;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcasn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes
{
    ASN1ObjectIdentifier  smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
    ASN1ObjectIdentifier  encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}
