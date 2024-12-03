import org.junit.jupiter.api.Test;
import presentation.NvdMirror;
import presentation.PiqueData;
import presentation.PiqueDataFactory;

public class NVDTest {

    @Test
    public void testNvdMirror() {
        PiqueDataFactory piqueDataFactory = new PiqueDataFactory();
        NvdMirror nvdMirror = piqueDataFactory.getNvdMirror();
        nvdMirror.buildAndHydrateMirror();
    }


}
