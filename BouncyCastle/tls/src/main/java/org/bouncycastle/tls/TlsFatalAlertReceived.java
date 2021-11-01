package org.bouncycastle.tls;

public class TlsFatalAlertReceived
    extends TlsException
{
    protected short alertDescription;

    public TlsFatalAlertReceived(short alertDescription)
    {
        super(AlertDescription.getText(alertDescription));

        this.alertDescription = alertDescription;
    }

    public short getAlertDescription()
    {
        return alertDescription;
    }
}
