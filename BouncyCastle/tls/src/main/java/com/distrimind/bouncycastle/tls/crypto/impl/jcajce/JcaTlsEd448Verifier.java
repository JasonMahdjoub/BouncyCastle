package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

public class JcaTlsEd448Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd448Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed448, "Ed448");
    }
}
