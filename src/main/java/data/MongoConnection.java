package data;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

import java.util.Arrays;

public class MongoConnection {
    private static MongoClient mongoClient = null;

    private MongoConnection() {}

    public static MongoClient getInstance(String username, String password, String hostname, String port, String authenticationDB) {
        if (mongoClient == null) {
            synchronized (MongoClient.class) {
                if (mongoClient == null) {
                    MongoCredential credential = MongoCredential.createCredential(username, authenticationDB, password.toCharArray());
                    mongoClient = MongoClients.create(
                            MongoClientSettings.builder()
                                    .applyToClusterSettings(builder ->
                                            builder.hosts(Arrays.asList(new ServerAddress(hostname, Integer.parseInt(port)))))
                                    .credential(credential)
                                    .build());
                }
            }
        }

        return mongoClient;
    }
}
