package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw ECDSA signature type using the JCA.
 */
public class JcaTlsECDSAVerifier
    extends JcaTlsDSSVerifier
{
    public JcaTlsECDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ecdsa, "NoneWithECDSA");
    }
}
