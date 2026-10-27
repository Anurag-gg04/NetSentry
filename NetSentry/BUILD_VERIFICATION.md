# Build and verification notes

The checks available in the packaging environment are listed here so the build status is clear.

- Java 21 is available; the project targets Java 17.
- Dashboard JavaScript syntax is checked with `node --check`.
- The HTML document, Maven XML, JSON configuration files, and bundled CSV headers are checked with local parsers.
- The Maven test suite could not be run in this environment because Maven is not installed and external package downloads are unavailable. No successful Maven build, JUnit run, or executable-JAR test is claimed here.

Before submitting or releasing the project, run the following from the project root on a machine with Java 17+ and Maven 3.9+:

```bash
mvn clean test package
java -jar target/netsentry.jar web
```

Then open `http://localhost:8080`, analyze `samples/mixed.csv`, inspect the alert and correlation pages, create an incident, update its status/assignee/notes, and confirm the incident remains after restarting the application.
