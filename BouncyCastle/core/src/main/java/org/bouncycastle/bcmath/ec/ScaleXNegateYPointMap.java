package org.bouncycastle.bcmath.ec;

public class ScaleXNegateYPointMap implements ECPointMap
{
    protected final ECFieldElement scale;

    public ScaleXNegateYPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public ECPoint map(ECPoint p)
    {
        return p.scaleXNegateY(scale);
    }
}
