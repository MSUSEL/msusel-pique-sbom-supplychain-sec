# Working With Data
![Start Trek NG Data](DataTNG.jpg)

This whole readme is going to be deleted or refactored but I wanted somewhere to write instructions in the meantime.
For the moment you need to manually set up mongodb/docker on your system. Instructions follow. There are some aspects
of the data access layer that are not complete including some of the standard db operations such as delete. This shouldn't
be a problem as we only write to the db from the NVD and never otherwise mutate the content.

Just be aware that the data
access layer is not totally complete and the tests may not all pass. I will be actively developing this over the coming week
or two and will update with PRs. Note that I have left in commented code handling the old python port. This will be removed soon
but I wanted to leave it for reference for the moment.

--------------------

### Local MongoDB Setup
This will all be automated at some point in the near future.

Be sure that you have installed the following on your computer
* docker
* docker-compose(may come bundled with docker - double check)
* MongoDB Compass
* mongosh

It's likely that all can be installed with apt/apt-get/snaps.

1. Pull and run the mongodb community docker image with the following command. Note this will create a persistent volume on your
computer that will require 250M - 500M of space. This is an unauthenticated local database running over localhost. I am working
orchestrating this whole process with docker-compose. We will eventually have a config that switches between a local database and
connecting to a persistent database.


```
docker run -v nvd-mirror:/data/db --name mongodb -p 27017:27017 -d mongodb/mongodb-community-server:latest
```

2. Run the `testDataStoreFullBuild()` test in `src/test/java/DataStoreTests.java` This will take between 6 and 10 minutes.

3. Run SBOM wrapper as normal. Let me know if you run into any unexpected errors.


