package data;

import com.mongodb.MongoClientException;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utilities.helperFunctions;

import java.io.IOException;
import java.util.*;

/**
 * Creates and manages a Singleton Mongo Connection
 */
public class MongoConnection {
    private static final Logger LOGGER = LoggerFactory.getLogger(MongoConnection.class);
    private static volatile MongoClient mongoClient = null;

    private MongoConnection() {}

    /**
     * Builds a MongoClient instance if one does not already exist.
     * This uses the MongoClient class to manage the connection pool.
     *
     * @return existing MongoClient or a new one if one does not already exist
     */
    public static MongoClient getInstance() {
        String username, password, port, hostname, dbname;
        Map<String, String> credentials;

        try {
            credentials = helperFunctions.getMongoCredentials();
        } catch (IOException e) {
            LOGGER.error("Could not read credentials file", e);
            throw new RuntimeException(e);
        }

        username = credentials.get("username");
        password = credentials.get("password");
        hostname = credentials.get("hostname");
        port = credentials.get("port");
        dbname = credentials.get("dbname");

        if (mongoClient == null) {
            synchronized (MongoClient.class) {
                if (mongoClient == null) {
                    MongoCredential credential = MongoCredential.createCredential(username, dbname, password.toCharArray());
                    try {
                        mongoClient = MongoClients.create(
                                MongoClientSettings.builder()
                                        .applyToClusterSettings(builder ->
                                                builder.hosts(Arrays.asList(new ServerAddress(hostname, Integer.parseInt(port)))))
                                        .credential(credential)
                                        .build());
                    } catch (MongoClientException e) {
                        LOGGER.error(String.format("Could not connect to Mongo database: {%s}.", dbname), e);
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        return mongoClient;
    }


}
