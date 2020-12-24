:+1:
```
    _    ____ ___   ____  _____ ____ _   _ ____  ___ _______   __
   / \  |  _ \_ _| / ___|| ____/ ___| | | |  _ \|_ _|_   _\ \ / /
  / _ \ | |_) | |  \___ \|  _|| |   | | | | |_) || |  | |  \ V / 
 / ___ \|  __/| |   ___) | |__| |___| |_| |  _ < | |  | |   | |  
/_/   \_\_|  |___| |____/|_____\____|\___/|_| \_\___| |_|   |_|  
                                                                 

```

## What is API Security ?

### API Styles
- Remote Procedure Call (RPC)
  * RPC APIs often use compact binary formats for messages and are very efficient, but usu- ally require the client to install specific libraries (known as stubs) that work with a single API.
  * The gRPC framework from Google (https://grpc.io) is an example of a modern RPC approach.
  * The older SOAP (Simple Object Access Protocol) framework, which uses XML for messages
- Remote Method Invocation (RMI)
  * Uses object oriented techniques to allow clients to call methods on remote objects as if they were local.
  * Technologies such as CORBA and Enterprise Java Beans (EJBs) often used for building large enterprise systems.
  * The complexity of these frameworks has led to a decline in their use.
- REST (REpresentational State Transfer)
  * In contrast to RPC, RESTful APIs emphasize standard message formats and a small number of generic operations to reduce the coupling between a client and a specific API.
- GraphQL
  * APIs are mostly concerned with efficient querying and filtering of large data sets, such as SQL databases or the GraphQL framework.
  * The API often only provides a few operations and a complex query language allows the client significant control over what data is returned.
  
### API security in context
- Information security (InfoSec)
  > The protection of information over its full life cycle from creation, storage, transmission, backup, and eventual destruction.  
  * Define your security goals and identify threats
  * Protect your APIs using access control techniques 
  * Secure information using applied cryptography
- Network security 
  > The protection of data flowing over a network and prevention of unauthorized access to the network itself.
  * The basic infrastructure used to protect an API on the internet, including firewalls, load-balancers, and reverse proxies, and roles they play in protecting your API (see the next section)
  * Use of secure communication protocols such as HTTPS to protect data trans- mitted to or from your API
- Application security (AppSec)
  > Software systems are designed and built to withstand attacks and misuse.
  * Secure coding techniques
  * Common software security vulnerabilities
  * How to store and manage system and user credentials used to access your APIs

### A typical API deployment

- Internet -> Load Balancer -> Reverse Proxy (or gateway) -> Application

  > A reverse proxy (or gateway) is typically placed in front of the application servers to perform computationally expensive operations like handling TLS encryption (known as SSL termination) and validating credentials on requests.
  
- SSL Termination
  > SSL termination1 (or SSL offloading) occurs when a TLS connection from a client is handled by a load balancer or reverse proxy in front of the destination API server.
  
- Some more specialist services:
  * API gateway is a specialized reverse proxy
    > API gateways can often also take care of some of the aspects of API security, such as authentication or rate-limiting.  
  * Web Application Firewall (WAF)
    > Inspects traffic at a higher level than a traditional firewall
  * Intrusion detection system (IDS) or intrusion prevention system (IPS) 
    > It detects suspicious patterns of activity it can either raise an alert or actively attempt to block the suspicious traffic.
    
### Elements of API security
- Assets
  * The assets will consist of information, such as customer names and addresses, credit card information, and the contents of databases.
- Security goals
  * There is no single definition of security, and some definitions can even be contradictory.
  * “CIA Triad”
    * Confidentiality
      > Ensuring information can only be read by its intended audience.
    * Integrity
      > Preventing unauthorized creation, modification, or destruction of information.
    * Availability
      > The legitimate users of an API can access it when they need.
  * Accountability
    > who did what
  * Non-Repudiation
    > not being able to deny having performed an action
- Environments and threat models
  * The goal of threat modeling is to identify these general threats, not to enumerate every possible attack.
  * One very popular methodology is known by the acronym **STRIDE**, which stands for:
    * Spoofing — Pretending to be somebody else.
    * Tampering — Altering data, messages, or settings you’re not supposed to alter.
    * Repudiation — Denying that you did something that you really did do.
    * Information disclosure — Revealing information that should be kept private.
    * Denial of service — Preventing others from accessing information and services.
    * Elevation of privilege — Gaining access to functionality you’re not supposed to have access to.

### Security mechanisms
- Encryption
  * data in transit
  * data at rest
- Authentication
- Access control (also known as authorization)
  * Identity-based access control
    > first identifies the user and then determines what they can do based on who they are.
  * Capability-based access control
    > special tokens or keys known as capabilities to access an API.
- Audit logging
  * Who performed the action and what client did they use?
  * When was the request received?
  * What kind of request was it, such as a read or modify operation? 
  * What resource was being accessed?
  * Was the request successful? If not, why?
  * What other requests did they make around the same time?
- Rate-limiting
  * A rate-limiter can either completely close connections when the limit is exceeded or else slow down the processing of requests, a process known as throttling.