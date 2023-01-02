package com.distrimind.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
//import java.util.logging.Level;
//import java.util.logging.Logger;

import com.distrimind.bouncycastle.bcpg.BCPGInputStream;
import com.distrimind.bouncycastle.bcpg.Packet;
import com.distrimind.bouncycastle.bcpg.PacketTags;
import com.distrimind.bouncycastle.bcpg.SignaturePacket;
import com.distrimind.bouncycastle.bcpg.TrustPacket;
import com.distrimind.bouncycastle.bcpg.UnsupportedPacketVersionException;
import com.distrimind.bouncycastle.bcpg.UserAttributePacket;
import com.distrimind.bouncycastle.bcpg.UserDataPacket;
import com.distrimind.bouncycastle.bcpg.UserIDPacket;

/**
 * Parent class for PGP public and secret key rings.
 */
public abstract class PGPKeyRing
{
    //private static final Logger LOG = Logger.getLogger(PGPKeyRing.class.getName());

    PGPKeyRing()
    {
    }

    static TrustPacket readOptionalTrustPacket(
        BCPGInputStream pIn)
        throws IOException
    {
        int tag = pIn.skipMarkerPackets();

        return tag == PacketTags.TRUST ? (TrustPacket)pIn.readPacket() : null;
    }

    static List<PGPSignature> readSignaturesAndTrust(
        BCPGInputStream pIn)
        throws IOException
    {
        List<PGPSignature> sigList = new ArrayList<PGPSignature>();

        while (pIn.skipMarkerPackets() == PacketTags.SIGNATURE)
        {
            try
            {
                SignaturePacket signaturePacket = (SignaturePacket)pIn.readPacket();
                TrustPacket trustPacket = readOptionalTrustPacket(pIn);

                sigList.add(new PGPSignature(signaturePacket, trustPacket));
            }
            catch (UnsupportedPacketVersionException e)
            {
                // skip unsupported signatures
                //if (LOG.isLoggable(Level.FINE))
                //{
                    //LOG.fine("skipping unknown signature: " + e.getMessage());
                //}
            }
        }
        return sigList;
    }

    static void readUserIDs(
        BCPGInputStream pIn,
        List<UserDataPacket> ids,
        List<TrustPacket> idTrusts,
        List<List<PGPSignature>> idSigs)
        throws IOException
    {
        while (isUserTag(pIn.skipMarkerPackets()))
        {
            Packet obj = pIn.readPacket();
            if (obj instanceof UserIDPacket)
            {
                UserIDPacket id = (UserIDPacket)obj;
                ids.add(id);
            }
            else
            {
                UserAttributePacket user = (UserAttributePacket)obj;
                ids.add(new PGPUserAttributeSubpacketVector(user.getSubpackets()));
            }

            idTrusts.add(readOptionalTrustPacket(pIn));
            idSigs.add(readSignaturesAndTrust(pIn));
        }
    }

    /**
     * Return the first public key in the ring.  In the case of a {@link PGPSecretKeyRing}
     * this is also the public key of the master key pair.
     *
     * @return PGPPublicKey
     */
    public abstract PGPPublicKey getPublicKey();

    /**
     * Return an iterator containing all the public keys.
     *
     * @return Iterator
     */
    public abstract Iterator<PGPPublicKey> getPublicKeys();

    /**
     * Return the public key referred to by the passed in keyID if it
     * is present.
     *
     * @param keyID the full keyID of the key of interest.
     * @return PGPPublicKey with matching keyID.
     */
    public abstract PGPPublicKey getPublicKey(long keyID);

    /**
     * Return the public key with the passed in fingerprint if it
     * is present.
     *
     * @param fingerprint the full fingerprint of the key of interest.
     * @return PGPPublicKey with the matching fingerprint.
     */
    public abstract PGPPublicKey getPublicKey(byte[] fingerprint);

    /**
     * Return an iterator containing all the public keys carrying signatures issued from key keyID.
     *
     * @return a an iterator (possibly empty) of the public keys associated with keyID.
     */
    public abstract Iterator<PGPPublicKey> getKeysWithSignaturesBy(long keyID);

    public abstract void encode(OutputStream outStream)
        throws IOException;

    public abstract byte[] getEncoded()
        throws IOException;

    private static boolean isUserTag(int tag)
    {
        switch (tag)
        {
        case PacketTags.USER_ATTRIBUTE:
        case PacketTags.USER_ID:
            return true;
        default:
            return false;
        }
    }
}
