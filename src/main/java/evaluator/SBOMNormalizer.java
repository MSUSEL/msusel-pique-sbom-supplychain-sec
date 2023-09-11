package evaluator;

import pique.evaluation.Normalizer;
import pique.utility.BigDecimalWithContext;
import utilities.helperFunctions;

import java.math.BigDecimal;

public class SBOMNormalizer extends Normalizer {
    @Override
    //inValue is a non-normalized value for a measure
    public BigDecimal normalize(BigDecimal inValue) {
        BigDecimal packageCount = new BigDecimalWithContext(helperFunctions.getComponentCount());
        return inValue.divide(packageCount,BigDecimalWithContext.getMC());
    }
}
