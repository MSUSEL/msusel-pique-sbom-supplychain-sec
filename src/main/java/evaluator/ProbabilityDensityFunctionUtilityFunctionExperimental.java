package evaluator;

import pique.evaluation.ProbabilityDensityFunctionUtilityFunction;

import java.math.BigDecimal;

public class ProbabilityDensityFunctionUtilityFunctionExperimental extends ProbabilityDensityFunctionUtilityFunction {

    public static double currentBandwidth = 1;
    public static int currentSamplingSpace = 1000;

    public ProbabilityDensityFunctionUtilityFunctionExperimental() {
        super();
        super.setName("evaluator.ProbabilityDensityFunctionUtilityFunctionExperimental");
        super.setBandwidth(10);
        super.setSamplingSpace(10000);
    }

    public ProbabilityDensityFunctionUtilityFunctionExperimental(double bandwidth, int samplingSpace, String kernelFunction) {
        super();
        super.setName("evaluator.ProbabilityDensityFunctionUtilityFunctionExperimental");
        super.setBandwidth(bandwidth);
        super.setSamplingSpace(samplingSpace);
        // TODO set kernel function
    }

    @Override
    public BigDecimal utilityFunction(BigDecimal inValue, BigDecimal[] thresholds, boolean positive) {
        super.setBandwidth(currentBandwidth);
        super.setSamplingSpace(currentSamplingSpace);
        return super.utilityFunction(inValue, thresholds, positive);
    }
}
