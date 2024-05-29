package data.handlers;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import data.cveData.CveDetails;
import data.interfaces.IJsonMarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CveDetailsMarshaller implements IJsonMarshaller<CveDetails> {
    private static final Logger LOGGER = LoggerFactory.getLogger(CveDetailsMarshaller.class);

    @Override
    public CveDetails unmarshallJson(String json) {
        try {
            return new Gson().fromJson(json, CveDetails.class);
        } catch (JsonSyntaxException e) {
            LOGGER.error("Incorrect JSON syntax - unable to parse to object", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public String marshallJson(CveDetails cveDetails) {
        return new Gson().toJson(cveDetails);
    }
}
