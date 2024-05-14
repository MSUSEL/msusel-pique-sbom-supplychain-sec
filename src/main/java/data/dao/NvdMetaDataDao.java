package data.dao;

import com.mongodb.MongoCredential;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.result.UpdateResult;
import data.MongoConnection;
import data.NvdMirrorMetadata;
import data.Utils;
import data.cveData.CVEResponse;
import data.handlers.NvdCveMarshaller;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pique.utility.PiqueProperties;

import java.util.List;
import java.util.Properties;

public class NvdMetaDataDao {
    private final MongoClient client = MongoConnection.getInstance();
    private final MongoDatabase db = client.getDatabase("nvdMirror");
    private final MongoCollection<Document> vulnerabilities = db.getCollection("vulnerabilities");
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdMetaDataDao.class);
    private final Document metadataFilter = new Document("_id", "nvd_metadata");

    public void insert(CVEResponse cveResponse) {
        Document metadata = generateMetadata(cveResponse);
        long documentCount = vulnerabilities.countDocuments(metadataFilter);
        if(documentCount == 0) {
            vulnerabilities.insertOne(metadata);
        }
    }

    public void replace(CVEResponse cveResponse) {
        Document metadata = generateMetadata(cveResponse);
        ReplaceOptions opts = new ReplaceOptions().upsert(true);
        UpdateResult updateResult = vulnerabilities.replaceOne(metadataFilter, metadata, opts);

        System.out.println("Modified document count: " + updateResult.getModifiedCount());
        System.out.println("Upserted id: " + updateResult.getUpsertedId());
    }

    public NvdMirrorMetadata get(Document criteria) {
        NvdMirrorMetadata nvdMirrorMetadata = new NvdMirrorMetadata();
        Document result = vulnerabilities.find(Filters.eq(criteria)).first();
        assert result != null;

        nvdMirrorMetadata.setId(result.get("id").toString());
        nvdMirrorMetadata.setTotalResults(result.get("totalResults").toString());
        nvdMirrorMetadata.setFormat(result.get("format").toString());
        nvdMirrorMetadata.setVersion(result.get("version").toString());
        nvdMirrorMetadata.setTimestamp(result.get("timestamp").toString());

        return nvdMirrorMetadata;
    }

    private Document generateMetadata(CVEResponse cveResponse) {
        return new Document("_id", "nvd_metadata")
                .append("totalResults", cveResponse.getTotalResults())
                .append("format", cveResponse.getFormat())
                .append("version", cveResponse.getVersion())
                .append("timestamp", cveResponse.getTimestamp());
    }
}
