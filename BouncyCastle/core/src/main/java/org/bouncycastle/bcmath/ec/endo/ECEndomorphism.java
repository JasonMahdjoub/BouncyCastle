package org.bouncycastle.bcmath.ec.endo;

import org.bouncycastle.bcmath.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
