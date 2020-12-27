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
  

## Secure API development

### Setup
- Java 11
- Spark Java: http://sparkjava.com
- H2 in-memory database: https://h2database.com
- Dalesbred database abstraction library: https://dalesbred.org

### Initialize Database
- Two entities: 
  * spaces
    * space_id
    * name
    * owner 
  * messages
    * msg_id
    * author
    * msg_time
    * msg_txt
    * space_id

### Trying it out
> mvn clean compile exec:java

>  curl -i -d '{"name": "test space", "owner": "demo"}' http://localhost:4567/spaces


### Injection attacks
#### Preventing Injection Attacks
- The best approach is to ensure that user input is always clearly separated from dynamic code by using APIs that support prepared statements.
#### Mitigating SQL injection with permissions
- While prepared statements should be your number one defense against SQL injection attacks, another aspect of the attack worth mentioning is that the database user didn’t need to have permissions to delete tables in the first place.
- The **principle of least authority** says that you should only grant users and processes the fewest permissions that they need to get their job done and no more.

### Input validation
### Producing safe output
#### XSS: Cross Site Scripting
> To appreciate why XSS is such a risk, you need to understand that the security model of web browsers is based on the same-origin policy (SOP). Scripts executing within the same origin (or same site) as a web page are, by default, able to read cookies set by that website, examine HTML elements created by that site, make network requests to that site, and so on, although scripts from other origins are blocked from doing those things.

> A successful XSS allows an attacker to execute their script as if it came from the target origin, so the malicious script gets to do all the same things that the genuine scripts from that origin can do.

#### Exploiting XSS Attacks
```
afterAfter((request, response) -> {
      response.header("X-XSS-Protection", "0");
});
```

- The X-XSS-Protection header is usually used to ensure browser protections are turned on, but in this case, you’ll turn them off temporarily to allow the bug to be exploited.

#### Preventing XSS
- There are some standard security headers that you can add to all API responses to add additional protection for web browser clients

|Security header|Description|Comments|
|---------------|-----------|--------|
|X-XSS-Protection|Tells the browser whether to block/ignore suspected XSS attacks.|The current guidance is to set to “0” on API responses to completely disable these protections due to security issues they can introduce.|
|X-Content-Type-Options|Set to nosniff to pre- vent the browser guess- ing the correct Content- Type.|Without this header, the browser may ignore your Content-Type header and guess (sniff) what the content really is. This can cause JSON output to be interpreted as HTML or JavaScript, so always add this header.|
|X-Frame-Options|Set to DENY to prevent your API responses being loaded in a frame or iframe.|In an attack known as drag ‘n’ drop clickjacking, the attacker loads a JSON response into a hidden iframe and tricks a user into dragging the data into a frame controlled by the attacker, potentially revealing sensitive information. This header pre- vents this attack in older browsers but has been replaced by Content Security Policy in newer browsers (see below). It is worth setting both headers for now.|
|Cache-Control and Expires|Controls whether brows- ers and proxies can cache content in the response and for how long.|These headers should always be set correctly to avoid sensitive data being retained in the browser or network caches. It can be useful to set default cache headers in a before() filter, to allow spe- cific endpoints to override it if they have more specific caching requirements. The safest default is to disable caching completely using the no-store directive and then selectively re-enable caching for individual requests if necessary. The Pragma: no-cache header can be used to disable caching for older HTTP/1.0 caches.|
|Content-Security-Policy|Reduce the scope for XSS attacks by restricting where scripts can be loaded from and what they can do.||

- Recommended CSP directives for REST responses

|Security Header|Value|Comments|
|---------------|-----|--------|
|default-src|'none'|Prevents the response from loading any scripts or resources.|
|frame-ancestors|'none'|A replacement for X-Frame-Options, this prevents the response being loaded into an iframe.|
|sandbox|n/a|Disables scripts and other potentially dangerous content from being executed.|

