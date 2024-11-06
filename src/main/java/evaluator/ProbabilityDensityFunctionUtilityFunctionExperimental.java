package evaluator;

import pique.evaluation.ProbabilityDensityFunctionUtilityFunction;

public class ProbabilityDensityFunctionUtilityFunctionExperimental extends ProbabilityDensityFunctionUtilityFunction {

    public ProbabilityDensityFunctionUtilityFunctionExperimental() {
        super();
        super.setName("evaluator.ProbabilityDensityFunctionUtilityFunctionExperimental");
        super.setBandwidth(10);
        super.setSamplingSpace(10000);
    }
}
