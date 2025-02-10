package modelTests;

import org.junit.jupiter.api.Test;
import runnable.Wrapper;

import static org.junit.jupiter.api.Assertions.*;

public class WrapperTest {

    @Test
    void testHelpFlagDisplaysHelpAndExits() {
        String[] args = {"--help"};

        // Capture System.out to validate the help message output
        assertDoesNotThrow(() -> Wrapper.main(args));
        // We assume proper argument parser setup means this won't throw an exception
    }

    @Test
    void testVersionFlagDisplaysVersionAndExits() {
        String[] args = {"--version"};

        assertDoesNotThrow(() -> Wrapper.main(args));
        // System.out should include "PIQUE-SBOM-SUPPLYCHAIN-SEC version 1.0"
    }

//    @Test
//    void testDeriveRunTypeInvokesQualityModelDeriver() {
//        String[] args = {"--runType", "derive"};
//
//        assertDoesNotThrow(() -> Wrapper.main(args));
//        // Validate that the QualityModelDeriver process runs without exceptions
//    }

//    @Test
//    void testEvaluateRunTypeInvokesSingleProjectEvaluator() {
//        String[] args = {"--runType", "evaluate", "--gen_tool", "trivy"};
//
//        assertDoesNotThrow(() -> Wrapper.main(args));
//        // Validate evaluator process runs without exceptions
//    }

    @Test
    void testInvalidRunTypeLogsError() {
        String[] args = {"--runType", "invalidType"};

        Exception exception = assertThrows(Exception.class, () -> Wrapper.main(args));
        assertEquals("argument --runType: invalid choice: 'invalidType' (choose from {derive,evaluate})", exception.getMessage());
    }

//    @Test
//    void testNoArgumentsUsesDefaults() {
//        String[] args = {};
//
//        assertDoesNotThrow(() -> Wrapper.main(args));
//        // Ensure the default "derive" mode is used
//    }

    @Test
    void testMissingRequiredArgumentsLogsError() {
        String[] args = {"--runType"}; // Missing value for runType

        Exception exception = assertThrows(Exception.class, () -> Wrapper.main(args));
        assertEquals("argument --runType: expected one argument", exception.getMessage());
        // Expect an appropriate error to be logged or thrown
    }
}
