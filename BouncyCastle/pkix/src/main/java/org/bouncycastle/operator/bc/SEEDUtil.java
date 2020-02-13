package org.bouncycastle.operator.bc;

import org.bouncycastle.bcasn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

class SEEDUtil
{
    static AlgorithmIdentifier determineKeyEncAlg()
    {
        // parameters absent
        return new AlgorithmIdentifier(
            KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }
}
