# Data Access Cookbook

---

## Introduction
PIQUE uses two main external sources of data regarding known vulnerabilities. 
The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) maintained 
by The National Institutes of Standards and Technology (NIST) "is the U.S. government
repository of standards based vulnerability management data represented using the Security
Content Automation Protocol (SCAP)." (nvd.nist.gov, accessed 5/1/2024). The other is the
[GitHub Advisory Database (GHSA)](https://github.com/github/advisory-database). The NVD is 
accessed via a RESTful API whereas the GHSA offers a GraphQL endpoint and schema. The "data"
package contains programmatic tools to standardize and streamline consumption of these API's.
These tools include Request and Response objects for both the NVD and GHSA. Handlers, deserialization
utilities, and POJOs are included as well. Directions follow, but this is designed to be a plug-and-play
interface for consuming API's with PIQUE.

In addition to third-party API consumption, PIQUE is configured to work with a local mirror of
the entire NVD. This is a best practice suggested by NIST when working with large amounts of NVD data.
At MSU, this mirror is persistent and hosted on an on-prem server, but this mirror can be instantiated 
ephemerally using docker and MongoDB. Instructions for both options are included in !!!!!!XXXXXXXX SETUP DIRECTIONS !XXXXXXXXX!!!!!!!!!!!!!!!!

What follows are the recommended methods of accessing data for use with PIQUE. These opinionated tools 
provide classes necessary for authenticating, configuring, and executing calls to third-party
API's. They are designed with current needs in mind, but are extensible to allow for consumption
of new data sources. Additionally, PIQUE offers preconfigured tooling for building a mirror of the 
NVD using MongoDB and docker. Both API consumption utilities, and database access utilities are 
discussed in detail below.


## Consume The NVD CVE 2.0 API
_Before proceeding, recall that the local mirror will be more performant for almost every use case.
Instructions for the Data Access layer are located [here.]_

### Steps
1. Generate an NVD API Key [here.](https://nvd.nist.gov/developers/request-an-api-key)
   * Place that key in the \<project root directory>/input/nvd_key.txt (All on one line and without spaces)
2. Instantiate pique-properties file
3. Instantiate NVDRequestFactory
4. Build an NVDRequest Object with the NVDRequestFactory
5. Execute the request and store the handled response in the NVDResponse object

### Example Code
```java

    Properties prop = PiqueProperties.getProperties();
    List<String> apiKey = Arrays.asList("apiKey", helperFunctions.getAuthToken(prop.getProperty("nvd-api-key-path")));
    NVDRequestFactory nvdRequestFactory = new NVDRequestFactory();
  
    NVDRequest request = nvdRequestFactory.createNVDRequest(HTTPMethod.GET, Utils.NVD_BASE_URI, apiKey, START_INDEX, RESULTS_PER_PAGE);
    NVDResponse response = request.executeRequest();
  
    return response.getCveResponse();
```
### A Note About Rate Limits
The NVD imposes tiered rate limits on requests. All data is accessible without an API key, but 
rate limits are dramatically higher for requests made with a key. The NVD also encourages paginated
responses for large requests. The results per page parameter defines the maximum page size. This page
size is limited to a maximum of 2000 by NIST. For large requests, it is recommended to sleep your program
for a few seconds between calls.

## Consume the GitHub Vulnerability Database
The GHSA only offers a GraphQL endpoint. This provides a great deal of flexibility in crafting requests and
responses. With GraphQL, you form a request that complies with the endpoint's schema and you receive exactly and
only the data you query. Good practice is to maintain a copy of the official schema and use libraries to 
form type-safe queries that are guaranteed to match the schema. However, this creates overhead and maintenance
in the calling program. As such, we have elected to simply make GraphQL calls with raw strings that have been 
manually formatted to match the GHSA schema. If we extend our use of in the future, appropriate libraries should 
be used to validate queries.

### Steps
1. Generate a GitHub Personal Access Token. 
   * Instructions are located [here.](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
2. Define your query and ghsaId variable strings.
3. Create a properly-formatted JSONObject representation of your query and convert that to a String object.
4. Interpolate any variables
5. Instantiate GHSA Request and Response objects.
6. Format authentication header
7. Execute the request and store the handled response.

### Example Code
```java
    // Define variables
    String ghsaId = "GHSA-vh2m-22xx-q94f";

    JSONObject jsonBody = new JSONObject();
    
    // Format query as json
    jsonBody.put("query", GraphQlQueries.GHSA_SECURITY_ADVISORY_QUERY);
    String query = jsonBody.toString();
    
    // Insert variable (This is not GraphQL best practice, but suffices for now)
    String formattedQuery = String.format(query, ghsaId);

    // Format authentication and headers
    String githubToken = helperFunctions.getAuthToken(prop.getProperty("github-token-path"));
    String authHeader = String.format("Bearer %s", githubToken);
    List<String> headers = Arrays.asList("Content-Type", "application/json", "Authorization", authHeader);

    // Execute request
    GHSARequest ghsaRequest = new GHSARequest(HTTPMethod.POST, Utils.GHSA_URI, headers, formattedQuery);
    GHSAResponse ghsaResponse = ghsaRequest.executeRequest();
```

## Database Access
PIQUE uses the Data Access Object pattern for interacting with databases. This pattern separates the
business logic from the code managing access to databases. Because the implementation of any individual database
is not tightly coupled to the business logic, any database or datastore can be swapped in without affecting
the functioning of PIQUE. By default we use MongoDB to store CVE objects as Mongo Documents, but a relational
database could be easily used by implementing the IDao interface in a new concrete class. XXXThis secion needs workXXX



