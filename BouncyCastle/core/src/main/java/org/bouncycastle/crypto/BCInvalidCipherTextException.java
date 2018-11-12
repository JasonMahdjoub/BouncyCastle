package org.bouncycastle.crypto;

/**
 * this exception is thrown whenever we find something we don't expect in a
 * message.
 */
public class BCInvalidCipherTextException
    extends CryptoException
{
    /**
     * base constructor.
     */
    public BCInvalidCipherTextException()
    {
    }

    /**
     * create a BCInvalidCipherTextException with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public BCInvalidCipherTextException(
        String  message)
    {
        super(message);
    }

    /**
     * create a BCInvalidCipherTextException with the given message.
     *
     * @param message the message to be carried with the exception.
     * @param cause the root cause of the exception.
     */
    public BCInvalidCipherTextException(
        String  message,
        Throwable cause)
    {
        super(message, cause);
    }
}
