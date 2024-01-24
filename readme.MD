# Billing Management App

This project, developed for a school examination, leverages Spring Boot Microservices, Eureka Discovery, Gateway Service, Config Service, and Keycloak Integration, coupled with an Angular client.

## Description

### Dependencies

The project follows a distributed Spring microservices architecture, including:

- Gateway Service
- Configuration Service
- Discovery Service
- Customer Service
- Inventory Service
- Billing Service

### Installation

To set up the project:

1. Modify the application.properties files in the config service and set your configuration path.

### Execution

#### Execution Order

1. Discovery Service
2. Configuration Service
3. Gateway Service
4. Customer Service
5. Inventory Service
6. Billing Service
7. Angular Client

To run the Angular client:

```bash
cd ./PATH_TO_PROJECT/front
npm install
ng serve
```

## Authors

Contributor:
- CHAFIKI ZINEB
