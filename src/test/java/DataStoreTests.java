import org.junit.Test;
import data.NVDDataStore;

import java.io.IOException;
import java.net.URISyntaxException;

public class DataStoreTests {
    @Test
    public void TestBasicNVDRequest() throws IOException, URISyntaxException {
        NVDDataStore store = new NVDDataStore();
        store.initializeDataStore();
    }
}
