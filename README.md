# Custom Keycloak User Storage Provider for PeopleSoft
This provider can pull users from PSOPRDEFN in a PeopleSoft database and test authentication against a REST API in PeopleSoft.

This allows you to use PeopleSoft as a read-only backend for authentication in Keycloak

## Prepare Peoplesoft
1. Configure Integration Broker
    - PeopleTools -> Integration Broker -> Configuration -> Service Configuration
      - Setup REST URL in `Setup Target Locations`
2. Create REST Service
    - PeopleTools -> Integration Broker -> Configuration -> Web Services -> CI-Based REST Services
      - Search for `USERMAINT_SELF` and create `Get` method

## Build
    mvn clean install

## Deployment
Copy .jar to `$KEYCLOAK_HOME/providers`

Note: You will also need to place any .jar for JDBC driver that you will be utilizing in the `providers` directory as well
