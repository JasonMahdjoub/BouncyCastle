package com.distrimind.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.params.DHUPrivateParameters;
import com.distrimind.bouncycastle.crypto.params.DHUPublicParameters;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * FFC Unified static/ephemeral agreement as described in NIST SP 800-56A.
 */
public class DHUnifiedAgreement
{
    private DHUPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (DHUPrivateParameters)key;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("DHU", this.privParams.getStaticPrivateKey()));
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        DHUPublicParameters pubParams = (DHUPublicParameters)pubKey;

        DHBasicAgreement sAgree = new DHBasicAgreement();
        DHBasicAgreement eAgree = new DHBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        int fieldSize = getFieldSize();
        byte[] result = new byte[fieldSize * 2];
        BigIntegers.asUnsignedByteArray(eComp, result, 0, fieldSize);
        BigIntegers.asUnsignedByteArray(sComp, result, fieldSize, fieldSize);
        return result;
    }
}
