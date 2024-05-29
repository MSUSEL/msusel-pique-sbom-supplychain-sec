package data.handlers;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import data.cveData.CVEResponse;
import data.cveData.CveDetails;
import data.interfaces.IJsonMarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NvdCveMarshaller implements IJsonMarshaller<CVEResponse> {
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCveMarshaller.class);

    @Override
    public CVEResponse unmarshallJson(String json) {
        try {
            return new Gson().fromJson(json, CVEResponse.class);
        } catch (JsonSyntaxException e) {
            LOGGER.error("Incorrect JSON syntax - unable to parse to object", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public String marshallJson(CVEResponse cveResponse) {
        String json = new Gson().toJson(cveResponse);
        System.out.println(json);
        return new Gson().toJson(cveResponse);
    }
}
