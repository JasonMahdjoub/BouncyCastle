package com.distrimind.bouncycastle.openpgp;

import com.distrimind.bouncycastle.bcpg.BCPGKey;
import com.distrimind.bouncycastle.bcpg.DSASecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.bcpg.RSASecretBCPGKey;

/**
 * general class to contain a private key for use with other openPGP
 * objects.
 */
public class PGPPrivateKey
{
    private long          keyID;
    private PublicKeyPacket publicKeyPacket;
    private BCPGKey privateKeyDataPacket;

    public PGPPrivateKey(
        long              keyID,
        PublicKeyPacket   publicKeyPacket,
        BCPGKey           privateKeyDataPacket)
    {
        this.keyID = keyID;
        this.publicKeyPacket = publicKeyPacket;
        this.privateKeyDataPacket = privateKeyDataPacket;
    }

    /**
     * Return the keyID associated with the contained private key.
     * 
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }
    
    public PublicKeyPacket getPublicKeyPacket()
    {
        return publicKeyPacket;
    }

    public BCPGKey getPrivateKeyDataPacket()
    {
        return privateKeyDataPacket;
    }
}
