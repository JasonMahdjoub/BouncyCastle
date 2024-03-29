package com.distrimind.bouncycastle.cert.dane;

import com.distrimind.bouncycastle.util.Selector;

public class DANEEntrySelector
    implements Selector
{
    private final String domainName;

    DANEEntrySelector(String domainName)
    {
        this.domainName = domainName;
    }

    public boolean match(Object obj)
    {
        DANEEntry dEntry = (DANEEntry)obj;

        return dEntry.getDomainName().equals(domainName);
    }

    public Object clone()
    {
        return this;
    }

    public String getDomainName()
    {
        return domainName;
    }
}
