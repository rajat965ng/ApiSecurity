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

## Securing the Natter API

### Addressing threats with security controls
#### Encryption
- First, you need to generate a certificate that the API will use to authenticate itself to its clients.
- When a client connects to your API it will use a URI that includes the hostname of the server the API is running on, for example api .example.com. The server must present a certificate, signed by a trusted certificate authority (CA), that says that it really is the server for api.example.com. If an invalid certificate is presented, or it doesn’t match the host that the client wanted to connect to, then the client will abort the connection. Without this step, the client might be tricked into connecting to the wrong server and then send its password or other confidential data to the imposter.
- A tool called mkcert (https://mkcert.dev) simplifies the process considerably.
  ```
    mkcert -install
  ``` 
- A self-signed certificate is a certificate that has been signed using the private key associated with that same certificate, rather than by a trusted certificate authority.
- By default, mkcert generates certificates in Privacy Enhanced Mail (PEM) format. For Java, you need the certificate in PKCS#12 format, so run the following command in the root folder of the project to generate a certificate for localhost.
  ```
    mkcert -pkcs12 localhost
  ```
- Enable HTTPS support in Spark by adding a call to the secure() static method.
  ```
  curl -v --cacert "$(mkcert -CAROOT)/rootCA.pem" -d '{"username":"demo","password":"password"}' -H 'Content-Type: application/json' https://localhost:4567/users
  ```
- Strict transport security
  * API clients also often send sensitive data such as passwords on the first request so it is better to completely reject non-HTTPS requests. If for some reason you do need to support web browsers directly connecting to your API endpoints, then best practice is to immediately redirect them to the HTTPS version of the API and to set the HTTP Strict-Transport-Security (HSTS) header to instruct the browser to always use the HTTPS version in future. 
  * Set **Strict-Transport-Security** header.
#### Rate Limiting
- In a DNS amplification attack, the attacker sends the same DNS query to many DNS servers, spoofing their IP address to look like the request came from the victim. By carefully choosing the DNS query, the server can be tricked into replying with much more data than was in the original query, flooding the victim with traffic.
- Application layer DoS attacks attempt to overwhelm an API by sending valid requests, but at much higher rates than a normal client. 
- Rate-limiting should be the very first security decision made when a request reaches your API. Because the goal of rate-limiting is ensuring that your API has enough resources to be able to process accepted requests, you need to ensure that requests that exceed your API’s capacities are rejected quickly and very early in processing.
  * Rate-limiting with Guava
    * Often rate-limiting is applied at a reverse proxy, API gateway, or load balancer before the request reaches the API, so that it can be applied to all requests arriving at a cluster of servers.
    * Even if you enforce rate-limiting at a proxy server, it is good security practice to also enforce rate limits in each server so that if the proxy server misbehaves or is misconfigured, it is still difficult to bring down the individual servers.
    * This is an instance of the general security principle known as **defense in depth**, which aims to ensure that no failure of a single mechanism is enough to compromise your API.
      ```
          for i in {1..5}
          do
          curl -i -d "{\"owner\":\"test\",\"name\":\"space$i\"}" -H ‘Content-Type: application/json’ http://localhost:4567/spaces;
          done
      ```  

#### Authentication
- The process of verifying that a user is who they say they are.
- Authentication occurs after rate-limiting but before audit logging or access control. All requests proceed, even if authentication fails, to ensure that they are always logged. Unauthenticated requests will be rejected during access control, which occurs after audit logging.
- You can also outsource authentication to another organization using a federation protocol like SAML or OpenID Connect.
- Creating the password database
  * Create a 'user' table in schema.sql .
  * Scrypt takes several parameters to tune the amount of time and memory that it will use. 
  * which should take around 100ms on a single CPU and 32MiB of memory.
  * This may seem an excessive amount of time and memory, but these parameters have been carefully chosen based on the speed at which attackers can guess passwords. Dedicated password cracking machines, which can be built for relatively modest amounts of money, can try many millions or even billions of passwords per second. The expensive time and memory requirements of secure password hashing algorithms such as Scrypt reduce this to a few thousand passwords per second, hugely increasing the cost for the attacker and giving users valuable time to change their passwords after a breach is discovered.
  * The Scrypt library generates a unique random salt value for each password hash. The hash string that gets stored in the database includes the parameters that were used when the hash was generated, as well as this random salt value. This ensures that you can always recreate the same hash in future, even if you change the parameters.
    ```
    curl -v -d '{"name":"test space","owner":"demo"}' -H 'Content-Type: application/json' http://localhost:4567/spaces
    curl -v -d '{"username":"demo","password":"password"}' -H 'Content-Type: application/json' http://localhost:4567/users
    curl -v -u demo:password -d '{"name":"test space","owner":"demo"}' -H 'Content-Type: application/json' http://localhost:4567/spaces
    ```
#### Audit Logging
- Audit logging should occur after authentication, so that you know who is performing an action, but before you make authorization decisions that may deny access. The reason for this is that you want to record all attempted operations, not just the successful ones.
- Unsuccessful attempts to perform actions may be indications of an attempted attack.
- In a production environment you typically will want to send audit logs to a centralized log collection and analysis tool, known as a **SIEM (Security Information and Event Management)** system, so they can be correlated with logs from other systems and analyzed for potential threats and unusual behavior.
- For development, you’ll add a new database table to store the audit logs.
- You split the logging into two filters, one that occurs before the request is processed (after authentication), and one that occurs after the response has been produced.
- You should normally lock down audit logs to only a small number of trusted users, as they are often sensitive in themselves. Often the users that can access audit logs (auditors) are different from the normal system administrators, as administrator accounts are the most privileged and so most in need of monitoring. This is an important security principle known as **separation of duties**. 
  ```
  For example, a system administrator should not also be responsible for managing the audit logs for that system. In financial systems, separation of duties is often used to ensure that the person who requests a payment is not also the same person who approves the payment, providing a check against fraud.
  ```
  ```
  curl -v --cacert "$(mkcert -CAROOT)/rootCA.pem" https://localhost:4567/logs | jq
  ```  
#### Access Control
- The two main HTTP status codes for indicating that access has been denied are 401 Unauthorized and 403 Forbidden.
- The 403 Forbidden status code, on the other hand, tells the client that its credentials were fine for authentication, but that it’s not allowed to perform the operation it requested. This is a failure of authorization, not authentication.
- A simple filter that runs after authentication and verifies that a genuine subject has been recorded in the request attributes. If no subject attribute is found, then it rejects the request with a 401 status code and adds a standard ***WWW-Authenticate*** header to inform the client that the user should authenticate with Basic authentication.
  ```
  curl -v --cacert "$(mkcert -CAROOT)/rootCA.pem" -d '{"username":"demo","password":"password"}' -H 'Content-Type: application/json' https://localhost:4567/users
  curl -v --cacert "$(mkcert -CAROOT)/rootCA.pem" -u demo:password -d '{"name":"test space","owner":"demo"}' -H 'Content-Type: application/json' https://localhost:4567/spaces
  ```

##### Access control lists
- A very simple access control method based upon whether a user is a member of the social space they are trying to access.
- Accomplish this by keeping track of which users are members of which social spaces in a structure known as an access control list (ACL).
- Each entry for a space will list a user that may access that space, along with a set of permissions that define what they can do.

> For example, you might let anyone in your company see their own salary information in your payroll API, but the ability to change somebody’s salary is not normally something you would allow any employee to do! Recall the principle of least authority (POLA).

> Too many permissions and they may cause damage to the system. Too few permissions and they may try to work around the security of the system to get their job done.

##### Avoiding privilege escalation attacks
- A privilege escalation (or elevation of privilege) occurs when a user with limited permissions can exploit a bug in the system to grant themselves or somebody else more permissions than they have been granted.
- You can fix this in two general ways:
  * The permissions granted to the new user are no more than the permissions that are granted to the existing user. That is, you should ensure that evildemo2 is only granted the same access as the demo2 user.
  * Require that only users with all permissions can add other users.
  

## Session cookie authentication
- In token-based authentication, a user’s real credentials are presented once, and the client is then given a short-lived token.
- A token is typically a short, random string that can be used to authenticate API calls until the token expires.

### Authentication in web browsers
#### Calling the Natter API from JavaScript
- Use the Fetch interface in this example because it is much simpler and already widely supported by browsers.
#### Drawbacks of HTTP authentication (Basic Auth)
- The user’s password is sent on every API call, increasing the chance of it acci- dentally being exposed by a bug in one of those operations.
- Verifying a password is an expensive operation, and performing this validation on every API call adds a lot of overhead.
- The dialog box presented by browsers for HTTP Basic authentication is pretty ugly, with not much scope for customization. The user experience leaves a lot to be desired.
- There is no obvious way for the user to ask the browser to forget the password. On a public terminal, this is a serious security problem if the next user can visit pages using your stored password just by clicking the Back button.
#### Token-based authentication
- When a user logs in by presenting their username and password, the API will generate a random string (the token) and give it to the client. The client then presents the token on each subsequent request, and the API can look up the token in a database on the server to see which user is associated with that session.
- When the user logs out, or the token expires, it is deleted from the database, and the user must log in again if they want to keep using the API.

![](.README/61292950.png)

#### A token store abstraction
- TokenStore interface and its associated Token class as a UML class diagram. Each token has an associated username and an expiry time, and a collection of attributes that you can use to associate information with the token, such as how the user was authenticated or other details that you want to use to make access control decisions.
- Creating a token in the store returns its ID, allowing different store implementations to decide how the token should be named.

![](.README/cbf08cba.png)

#### Implementing token-based login
- The user controller authenticates the user with HTTP Basic authentication as before. If that succeeds, then the request continues to the token login endpoint, which can retrieve the authenticated subject from the request attributes. 
- Otherwise, the request is rejected because the endpoint requires authentication.

![](.README/46f8af44.png)


#### Session cookies
- After the user authenticates, the login endpoint returns a **Set-Cookie** header on the response.
- That instructs the web browser to store a random session token in the cookie storage.
- Subsequent requests to the same site will include the token as a **Cookie** header.

![](.README/d1d7261e.png)

- To access the session associated with a request, you can use the request.session() method.
```
Session session = request.session(true);
```
- To create a new session, you pass a true value, in which case Spark will generate a new session token and store it in its database. It will then add a Set-Cookie header to the response.
- If you pass a false value, then Spark will return null if there is no Cookie header on the request with a valid session token.

#### Avoiding session fixation attacks
- A session fixation attack occurs when an API fails to generate a new session token after a user has authenticated. 
- The attacker captures a session token from loading the site on their own device and then injects that token into the victim’s browser.
- Once the victim logs in, the attacker can use the original session token to access the victim’s account.

![](.README/399cb538.png)

- Browsers will prevent a site hosted on a different origin from setting cookies for your API, but there are still ways that session fixation attacks can be exploited.
- **The default, and safest, mechanism is to store the token in a cookie.**
- The **;JSESSIONID=...** bit is added by the container and is parsed out of the URL on sub- sequent requests. This style of session storage makes it much easier for an attacker to carry out a session fixation attack.
- Ensure that the session tracking-mode is set to COOKIE in your web.xml
```
<session-config>
    <tracking-mode>COOKIE</tracking-mode>
</session-config>
```

- prevent session fixation attacks by ensuring that any existing session is invalidated after a user authenticates. This ensures that a new random session identifier is generated, which the attacker is unable to guess. The attacker’s session will be logged out.
```

 var session = request.session(false);

 if (session != null) {
    session.invalidate(); 
 }
 session = request.session(true);
   
```

#### Cookie security attributes
- |Cookie Attribute|Meaning|
  |----------------|-------|
  |Secure|Secure cookies are only ever sent over a HTTPS connection and so cannot be stolen by network eavesdroppers.|
  |HttpOnly|Cookies marked HttpOnly cannot be read by JavaScript, making them slightly harder to steal through XSS attacks.|
  |SameSite|SameSite cookies will only be sent on requests that originate from the same origin as the cookie.|
  |Domain|If no Domain attribute is present, then a cookie will only be sent on requests to the exact host that issued the Set-Cookie header. This is known as a host-only cookie. If you set a Domain attribute, then the cookie will be sent on requests to that domain and all sub-domains.|
  |Path|If the Path attribute is set to /users, then the cookie will be sent on any request to a URL that matches /users or any sub-path such as /users/mary, but not on a request to /cats/mrmistoffelees. The Path defaults to the parent of the request that returned the Set-Cookie header, so you should normally explicitly set it to / if you want the cookie to be sent on all requests to your API. **The Path attribute has limited security benefits, as it is easy to defeat by creating a hidden iframe with the correct path and reading the cookie through the DOM.**|
  |Expires and Max-Age|Sets the time at which the cookie expires and should be forgotten by the client, either as an explicit date and time (Expires) or as the number of seconds from now (Max-Age).|
- The Secure and HttpOnly attributes should be set on any cookie used for security purposes.  
- Avoid setting a Domain attribute unless you absolutely need the same cookie to be sent to multiple sub-domains, because if just one sub-domain is compromised then an attacker can steal your session cookies.
> This typically occurs when a temporary site is created on a shared service like GitHub Pages and configured as a sub-domain of the main website. When the site is no longer required, it is deleted but the DNS records are often forgotten. An attacker can discover these DNS records and re-register the site on the shared web host, under the attacker's control. They can then serve their content from the compromised sub-domain.

#### Validating session cookies
- NA

### Preventing Cross-Site Request Forgery attacks
- The appeal of cookies as an API designer is that, once set, the browser will transparently add them to every request.
- Alas, this strength is also one of the greatest weaknesses of session cookies.
- The browser will also attach the same cookies when requests are made from other sites that are not your UI. Because you’re still logged in, the browser happily sends your session cookie along with those requests.

![](.README/c1b75dfc.png)

#### SameSite cookies
- When a cookie is marked as SameSite, it will only be sent on requests that originate from the same registerable domain that originally set the cookie.
- To mark a cookie as SameSite, you can add either SameSite=lax or SameSite=strict on the Set-Cookie header, just like marking a cookie as Secure or HttpOnly.

#### Hash-based double-submit cookies
- The most effective defense against CSRF attacks is to require that the caller prove that they know the session cookie, or some other unguessable value associated with the session.
- A common approach is to store this extra random token as a second cookie in the browser and require that it be sent as both a cookie and as an X-CSRF-Token header on each request. This second cookie is not marked HttpOnly, so that it can be read from JavaScript (but only from the same origin).
- This approach is known as a double-submit cookie, as the cookie is submitted to the server twice.

***This solution has some problems.***
- There are several ways that the cookie could be overwritten by the attacker with a known value, which would then let them forge requests.

***Solution***
- Make the second token be cryptographically bound to the real session cookie.
 
![](.README/88963438.png)

## Modern token-based authentication

> Cross-origin resource sharing (CORS) is a standard to allow some cross-origin requests to be permitted by web browsers. It defines a set of headers that an API can return to tell the browser which requests should be allowed.

### Allowing cross-domain requests with CORS
- Because the new site has a different origin
  * Attempting to send a login request from the new site is blocked because the JSON Content-Type header is disallowed by the same-origin policy (SOP).
  * Even if you could send the request, the browser will ignore any Set-Cookie headers on a cross-origin response, so the session cookie will be discarded.
  * You also cannot read the anti-CSRF token, so cannot make requests from the new site even if the user is already logged in.

#### Preflight requests
- A preflight request occurs when a browser would normally block the request for violating the same-origin policy. 
- The browser makes an HTTP OPTIONS request to the server asking if the request should be allowed.
- The server can either deny the request or else allow it with restrictions on the allowed headers and methods.

![](.README/7dc06d4d.png)

- The browser first makes an HTTP OPTIONS request to the target server. It includes the origin of the script making the request as the value of the Origin header, along with some headers indicating the HTTP method of the method that was requested (Access-Control-Request-Method header) and any nonstandard headers that were in the original request (Access-Control-Request-Headers).

#### CORS headers
- CORS headers that the server can send in the response

|CORS header|Response|Description|
|-----------|--------|-----------|
|Access-Control-Allow-Origin|Both|Specifies a single origin that should be allowed access, or else the wildcard * that allows access from any origin.|
|Access-Control-Allow-Headers|Preflight|Lists the non-simple headers that can be included on cross-origin requests to this server. The wildcard value * can be used to allow any headers.|
|Access-Control-Allow-Methods|Preflight|Lists the HTTP methods that are allowed, or the wildcard * to allow any method.|
|Access-Control-Allow-Credentials|Both|Indicates whether the browser should include cre- dentials on the request. Credentials in this case means browser cookies, saved HTTP Basic/Digest passwords, and TLS client certificates. If set to true, then none of the other headers can use a wildcard value.|
|Access-Control-Max-Age|Preflight|Indicates the maximum number of seconds that the browser should cache this CORS response. Browsers typically impose a hard-coded upper limit on this value of around 24 hours or less (Chrome currently limits this to just 10 minutes). This only applies to the allowed headers and allowed methods.|
|Access-Control-Expose-Headers|Actual|Only a small set of basic headers are exposed from the response to a cross-origin request by default. Use this header to expose any nonstandard headers that your API returns in responses.|

- If you return a specific allowed origin in the **Access-Control-Allow-Origin** response header, then you should also include a **Vary: Origin** header to ensure the browser and any network proxies only cache the response for this specific requesting origin.

#### Adding CORS headers to the API
- Because cookies are considered a credential by CORS, you need to return an **Access-Control-Allow-Credentials: true** header from preflight requests; otherwise, the browser will not send the session cookie.
- Browsers will also ignore any **Set-Cookie headers** in the response to a CORS request unless the response contains **Access-Control-Allow-Credentials: true**.

> SameSite cookies,are fundamentally incompatible with CORS. If a cookie is marked as SameSite, then it will not be sent on cross-site requests regardless of any CORS policy and the Access-Control-Allow-Credentials header is ignored.
> A complication came in October 2019, when Google announced that its Chrome web browser would start marking all cookies as SameSite=lax by default with the release of Chrome 80 in February 2020. (At the time of writing the rollout of this change has been temporarily paused due to the COVID-19 coronavirus pandemic.) If you wish to use cross-site cookies you must now explicitly opt-out of SameSite protections by adding the SameSite=none and Secure attributes to those cookies, but this can cause problems in some web browsers
> Google, Apple, and Mozilla are all becoming more aggressive in blocking cross-site cookies to prevent tracking and other security or privacy issues.

### Tokens without cookies
- Cookies are such a compelling option for web-based clients because they provide the three components needed to implement token-based authentication in a neat pre-packaged bundle.
  * A standard way to communicate tokens between the client and the server, in the form of the Cookie and Set-Cookie headers.
  * A convenient storage location for tokens on the client, that persists across page loads (and reloads) and redirections.
  * Simple and robust server-side storage of token state, as most web frameworks support cookie storage out of the box just like Spark.
- To replace cookies, you’ll therefore need a replacement for each of these three aspects

#### Storing token state in a database
- A token is a simple data structure that should be independent of dependencies on other functionality in your API.
-  A single table is enough to store this structure.
```
CREATE TABLE tokens(
    token_id VARCHAR(100) PRIMARY KEY,
    user_id VARCHAR(30) NOT NULL,
    expiry TIMESTAMP NOT NULL,
    attributes VARCHAR(4096) NOT NULL
);

GRANT SELECT, INSERT, DELETE ON tokens TO natter_api_user;    
```  
- To be secure, a token ID should be generated with a high degree of entropy from a cryptographically-secure random number generator (RNG).
> In information security, entropy is a measure of how likely it is that a random variable has a given value. When a variable is said to have 128 bits of entropy, that means that there is a 1 in 2^128 chance of it having one specific value rather than any other value. The more entropy a variable has, the more difficult it is to guess what value it has. If your API issues a very large number of tokens with long expiry times, then you should consider a higher entropy of 160 bits or more.   

#### The Bearer authentication scheme
- A standard way to pass non-cookie-based tokens to an API exists in the form of the Bearer token scheme for HTTP authentication.
- A bearer token can be given to a third party to grant them access without revealing user credentials but can also be used easily by attackers if stolen.
  
>eg. Authorization: Bearer QDAmQ9TStkDCpVK5A9kFowtYn2k

- if a client passed a token that has expired you could return:
> HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer realm="users", error="invalid_token", error_description="Token has expired"
  
#### Deleting expired tokens
- If tokens are not deleted, this also creates a potential DoS attack vector, because an attacker could keep logging in to generate enough tokens to fill the database storage.
- You should index the expiry column on the database, so that it does not need to loop through every single token to find the ones that have expired. Open schema.sql and add the following line to the bottom to create the index:
> CREATE INDEX expired_token_idx ON tokens(expiry);
- Finally, you need to schedule a periodic task to call the method to delete the expired tokens.
> DELETE FROM tokens WHERE expiry < current_timestamp

#### Storing tokens in Web Storage
- Update the UI to send the token in the Authorization header instead of in the X-CSRF-Token header.
- Alternatives to cookies for storing tokens in a web browser client.
  * The Web Storage API that includes the localStorage and sessionStorage objects for storing simple key-value pairs. **sessionStorage** is not shared between browser tabs or windows; each tab gets its own storage.
    * The sessionStorage object can be used to store data until the browser window or tab is closed.
    * The localStorage object stores data until it is explicitly deleted, saving the data even over browser restarts.
  * The IndexedDB API that allows storing larger amounts of data in a more sophisticated JSON NoSQL database.
- By replacing cookies for storage on the client, you will now have a replacement for all three aspects of token-based authentication provided by cookies.
  * On the backend, you can manually store cookie state in a database to replace the cookie storage provided by most web frameworks.
  * You can use the Bearer authentication scheme as a standard way to communicate tokens from the client to the API, and to prompt for tokens when not supplied.
  * Cookies can be replaced on the client by the Web Storage API.
  
![](.README/693f561b.png)  

#### Updating the CORS filter
- Now that your API no longer needs cookies to function, you can tighten up the CORS settings.
- Remove the **Access- Control-Allow-Credentials** headers to stop the browser sending any.
- Remove **X-CSRF-Token**.

#### XSS attacks on Web Storage
- Exfiltration is the act of stealing tokens and sensitive data from a page and sending them to the attacker without the victim being aware. The attacker can then use the stolen tokens to log in as the user from the attacker’s own device.
- ![](.README/d907e9fb.png)
- Although using **HttpOnly** cookies can protect against this attack.
- Two technologies are worth mentioning because they provide significant hardening against XSS:
  * Content-Security-Policy header (CSP): provides fine-grained control over which scripts and other resources can be loaded by a page and what they are allowed to do.
  * DOM-based XSS occurs when trusted Java- Script code accidentally allows user-supplied HTML to be injected into the DOM, such as when assigning user input to the .innerHTML attribute of an existing element. DOM-based XSS is notoriously difficult to prevent as there are many ways that this can occur, not all of which are obvious from inspection.
  
### Hardening database token storage
- As a first step, you should separate the database server from the API and ensure that the database is not directly accessible by external clients.
- Communication between the database and the API should be secured with TLS.  

#### Hashing database tokens
- You can use a fast, cryptographic hash function such as SHA-256 that you used for generating anti-CSRF tokens.
- ![](.README/19d38937.png)
- Because SHA-256 is a one-way hash function, an attacker that gains access to the database won’t be able to reverse the hash function to determine the real token IDs.
- To read or revoke the token, you simply hash the value provided by the user and use that to look up the record in the database.

#### Authenticating tokens with HMAC
- Simple hashing does not prevent **an attacker with write access** from inserting a fake token that gives them access to another user’s account.
- Most databases are also not designed to provide constant-time equality comparisons, so database lookups can be vulnerable to timing attacks.
- Eliminate both issues by calculating a **message authentica-tion code (MAC)**, such as the standard **hash-based MAC (HMAC)**. HMAC works like a normal cryptographic hash function, but incorporates a secret key known only to the API server.
- An attacker without access to the secret cannot compute a correct tag for any message. HMAC (hash-based MAC) is a widely used secure MAC based on a cryptographic hash function.
![](.README/ebcb6ef9.png)

##### GENERATING THE KEY
- Key used for HMAC-SHA256 is just a 32-byte random value, so you could generate one using a SecureRandom just like you currently do for database token IDs.
- Store the key in an external keystore that can be loaded by each server.

> A keystore is an encrypted file that contains cryptographic keys and TLS certificates used by your API. A keystore is usually protected by a password.

- Run the following command to generate a keystore with a 256-bit HMAC key:
  ```
   keytool -genseckey -keyalg HmacSHA256 -keysize 256 -alias hmac-key -keystore keystore.p12 -storetype PKCS12 -storepass changeit
  ```

## Self-contained tokens and JWTs
- **stateless tokens** that would allow you to get rid of the database entirely.  
- JSON Web Tokens (JWTs, pronounced “jots”) are a standard format for self-contained security tokens. 
- A JWT consists of a set of claims about a user represented as a JSON object, together with a header describing the format of the token. JWTs are cryptographically protected against tampering and can also be encrypted.

### Storing token state on the client

> Rather than store the token state in the database, you can instead encode that state directly into the token ID and send it to the client. 

- You could serialize the token fields into a JSON object, which you then **Base64url-encode** to create a string that you can use as the token ID. When the token is presented back to the API, you then simply decode the token and parse the JSON to recover the attributes of the session.

#### Protecting JSON tokens with HMAC
- Of course, as it stands, this code is completely insecure. Anybody can log in to the API and then edit the encoded token in their browser to change their username or other security attributes.
- By appending an authentication tag computed with a secret key known only to the API server, an attacker is prevented from either creating a fake token or altering an existing one.
```
curl -H 'Content-Type: application/json' -u test:password \
  -X POST https://localhost:4567/sessions
  {"token":"eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNTU5NTgyMTI5LCJhdHRycyI6e319.INFgLC3cAhJ8DjzPgQfHBHvU_uItnFjt568mQ43V7YI"}
```

![](.README/e5759ebc.png)

### JSON Web Tokens
- JWTs are very similar to the JSON tokens you have just produced, but have many more features:
  * A standard header format that contains metadata about the JWT, such as which MAC or encryption algorithm was used.
  * A set of standard claims that can be used in the JSON content of the JWT.
  * A wide range of algorithms for authentication and encryption, as well as digital signatures and public key encryption.
  
```
basic authenticated JWT = HMAC-authenticated JSON tokens +  an additional JSON header that indicates the algorithm and other details
```  

![](.README/bdcb95df.png)

>  JOSE is a kit-of-parts design, allowing develop- ers to pick and choose from a wide variety of algorithms, and not all combinations of features are secure.

> In 2015 the security researcher Tim McClean discovered vulnerabilities in many JWT libraries (http://mng.bz/awKz) in which an attacker could change the algorithm header in a JWT to influence how the recipient validated the token. It was even possible to change it to the value none, which instructed the JWT library to not validate the signature at all! 

#### The standard JWT claims

|Claim|Name|Purpose|
|-----|----|-------|
|iss|Issuer|Indicates who created the JWT. This is a single string and often the URI of the authentication service.|
|aud|Audience|Indicates who the JWT is for. An array of strings identifying the intended recipients of the JWT.|
|iat|Issued-At|The UNIX time at which the JWT was created.|
|nbf|Not-Before|The JWT should be rejected if used before this time.|
|exp|Expiry|The UNIX time at which the JWT expires and should be rejected by recipients.|
|sub|Subject|The identity of the subject of the JWT. A string. Usually a username or other unique identifier.|
|jti|JWT ID|A unique ID for the JWT, which can be used to detect replay.|

- Only the issuer, issued-at, and subject claims express a positive statement.
- The remaining fields all describe constraints on how the token can be used rather than making a claim. 
  * These constraints are intended to prevent certain kinds of attacks against security tokens, such as replay attacks in which a token sent by a genuine party to a service to gain access is captured by an attacker and later replayed so that the attacker can gain access.
  * Replay attacks are largely prevented by the use of TLS but can be important if you have to send a token over an insecure channel or as part of an authentication protocol.
  * If the attacker replays the token back to the original issuer, this is known as a reflection attack, and can be used to defeat some kinds of authentication protocols if the recipient can be tricked into accepting their own authentication messages. By verifying that your API server is in the audience list, and that the token was issued by a trusted party, these attacks can be defeated.

#### The JOSE header
- flexibility of the JOSE and JWT standards is concentrated in the header.
- For example, the following header indicates that the token is signed with HMAC-SHA-256 using a key with the given key ID:
```
    {
        "alg": "HS256",
        "kid": "hmac-key-1"
    }
```  
- It is recommended that they are stripped when possible to create (nonstandard) headless JWTs. 
  * This can be done by removing the header section produced by a standard JWT library before sending it and then recreating it again before validating a received JWT.
  
#### Generating standard JWTs

- Dependency
```
<dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>8.19</version>
</dependency>
```
- The Nimbus library requires a JWSSigner object for generating signatures, and a JWSVerifier for verifying them.
- These objects can often be used with several algorithms, so you should also pass in the specific algorithm to use as a separate JWSAlgorithm object.
- Finally, you should also pass in a value to use as the audience for the generated JWTs. 
- The serialize() method will then produce the JWS Compact Serialization of the JWT to return as the token identifier.

- Code

```
public class SignedJwtTokenStore implements TokenStore {

private final JWSSigner signer;
private final JWSVerifier verifier;
private final JWSAlgorithm algorithm;
private final String audience;
    
    public SignedJwtTokenStore(JWSSigner signer,JWSVerifier verifier, JWSAlgorithm algorithm,String audience) {
        this.signer = signer;
        this.verifier = verifier;
        this.algorithm = algorithm;
        this.audience = audience;
    }
    
    @Override
    public String create(Request request, Token token) {
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience(audience)
                .expirationTime(Date.from(token.expiry))
                .claim("attrs", token.attributes)
                .build();
                
        var header = new JWSHeader(JWSAlgorithm.HS256);
        var jwt = new SignedJWT(header, claimsSet);
        try {
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
    
}

Main.java

var algorithm = JWSAlgorithm.HS256;
var signer = new MACSigner((SecretKey) macKey);
var verifier = new MACVerifier((SecretKey) macKey);
TokenStore tokenStore = new SignedJwtTokenStore(signer, verifier, algorithm, "https://localhost:4567");
var tokenController = new TokenController(tokenStore);
```

- Usage
```
curl -H 'Content-Type: application/json' -u test:password -d '' https://localhost:4567/sessions

{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo0NTY3IiwiZXhwIjoxNTc3MDA3ODcyLCJhdHRycyI6e319.nMxLeSG6pmrPOhRSNKF4v31eQZ3uxaPVyj-Ztf-vZQw "}
```

#### Validating a signed JWT
- To validate a JWT, you first parse the JWS Compact Serialization format and then use the JWSVerifier object to verify the signature.
- The Nimbus MACVerifier will calculate the correct HMAC tag and then compare it to the tag attached to the JWT using a constant-time equality comparison, just like you did in the HmacTokenStore.

- Code
```
@Override
public Optional<Token> read(Request request, String tokenId) {
try {
    var jwt = SignedJWT.parse(tokenId);
    if (!jwt.verify(verifier)) {
        throw new JOSEException("Invalid signature");
    }
    
    var claims = jwt.getJWTClaimsSet();
    if (!claims.getAudience().contains(audience)) {
            throw new JOSEException("Incorrect audience");
    }
    
    var expiry = claims.getExpirationTime().toInstant();
    var subject = claims.getSubject();
    var token = new Token(expiry, subject);
    var attrs = claims.getJSONObjectClaim("attrs");
    attrs.forEach((key, value) -> token.attributes.put(key, (String) value));
    return Optional.of(token);
    } catch (ParseException | JOSEException e) {
        return Optional.empty();
    }
}
```
- Usage
```
curl -H 'Content-Type: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN
➥ 0IiwiYXVkIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo0NTY3IiwiZXhwIjoxNTc 
➥ 3MDEyMzA3LCJhdHRycyI6e319.JKJnoNdHEBzc8igkzV7CAYfDRJvE7oB2md 
➥ 6qcNgc_yM' -d '{"owner":"test","name":"test space"}' \
  https://localhost:4567/spaces

{"name":"test space","uri":"/spaces/1"}
```

### Encrypting sensitive attributes
#### Authenticated encryption with NaCl

```
<dependency>
      <groupId>software.pando.crypto</groupId>
      <artifactId>salty-coffee</artifactId>
      <version>1.0.2</version>
</dependency>
```

```
@Override
public String create(Request request, Token token) {
    var tokenId = delegate.create(request, token);
    return SecretBox.encrypt(encryptionKey, tokenId).toString();
}

@Override
public Optional<Token> read(Request request, String tokenId) {
    var box = SecretBox.fromString(tokenId);
    var originalTokenId = box.decryptToString(encryptionKey); return delegate.read(request, originalTokenId);
}

Main.java

var macKey = keyStore.getKey("hmac-key", keyPassword);
var encKey = keyStore.getKey("aes-key", keyPassword);
var naclKey = SecretBox.key(encKey.getEncoded());
var tokenStore = new EncryptedTokenStore(new JsonTokenStore(), naclKey);
var tokenController = new TokenController(tokenStore);
```

### Using types for secure API design
> Secure API design should make it very hard to write insecure code. It is not enough to merely make it possible to write secure code, because developers will make mistakes.

![](.README/6c23a8eb.png)


### Handling token revocation
- FWD

## OAuth2 and OpenID Connect

### Scoped tokens
- In the bad old days, if you wanted to use a third-party app or service to access your email or bank account, you had little choice but to give them your username and password and hope they didn’t misuse them.
  * Unfortunately, some services did misuse those credentials.
- Token-based authentication provides a solution to this problem by allowing you to generate a long-lived token that you can give to the third-party service instead of your password.
  * Though using a token means that you don’t need to give the third-party your password, the tokens you’ve used so far still grant full access to APIs as if you were performing actions yourself.
- The solution to these issues is to restrict the API operations that can be performed with a token, allowing it to be used only within a well-defined **scope**.
  * Typically, the scope of a token is represented as one or more string labels stored as an attribute of the token.
  * Eg. use the scope label **transactions:read** to allow read-access to transactions, and **payment:create** to allow setting up a new payment from an account.

#### Adding scoped tokens to Natter
- FWD
#### The difference between scopes and permissions
- When a user delegates some of their access to a third-party app or service, that is known as discretionary access control, because it’s up to the user how much of their access to grant to the third party.
- OAuth scopes are fundamentally about discretionary access control,

![](.README/cfa68e60.png)

|Permissions|Scope|
|-----------|-----|
|Permissions should be designed based on access control decisions that an administrator may want to make for individual users.|Scopes should be designed based on anticipating how users may want to delegate their access to third-party apps and services.|
||OAuth scopes used by Google for access to their Google Cloud Platform services.|
|Access to individual keys is managed through permissions instead.| Services that deal with system administration jobs, such as the Key Management Service for handling cryptographic keys, only have a single scope that grants access to that entire API.|
|permissions also identify the specific objects that can be accessed.|scopes typically only identify the set of API operations that can be performed.|

### Introducing OAuth2
- A user may not know which scopes are required for that application to function and so may create a token with too few scopes, or perhaps delegate all scopes just to get the application to work.
- A better solution is for the application to request the scopes that it requires, and then the API can ask the user if they consent.
- The tokens that an application uses to access an API are known as access tokens in OAuth2.

![](.README/85b41ed2.png)

- The authorization server (AS) authenticates the user and issues tokens to clients.
- The user is known as the resource owner (RO), because it’s typically their resources (documents, photos, and so on) that the third-party app is trying to access.
- The third-party app or service is known as the client.
- The API that hosts the user’s resources is known as the resource server (RS).

#### Types of clients

|Public clients|Confidential clients|
|--------------|--------------------|
|applications that run entirely within a user’s own device, such as a mobile app or JavaScript client running in a browser. |run in a protected web server or other secure location that is not under a user’s direct control.|
|The client is completely under the user’s control.|can have its own client credentials that it uses to authenticate to the authorization server.|

#### Authorization grants
- To obtain an access token, the client must first obtain consent from the user in the form of an authorization **grant** with appropriate scopes.
- The client then presents this grant to the AS’s token endpoint to obtain an access token.
- Resource Owner Password Credentials (ROPC)
  * The user supplies their username and password to the client, which then sends them directly to the AS to obtain an access token with any scope it wants.
  * It is not recommended for third-party clients because the user directly shares their password with the app.
  * The AS will authenticate the RO using the supplied credentials and, if successful, will return an access token in a JSON response.
  ```
  curl -d 'grant_type=password&client_id=test
  ➥ &scope=read_messages+post_message
  ➥ &username=demo&password=changeit'
  ➥ https://as.example.com:8443/oauth2/access_token
  
  
  {
            "access_token":"I4d9xuSQABWthy71it8UaRNM2JA",
            "scope":"post_message read_messages",
            "token_type":"Bearer",
            "expires_in":3599
  }
  ```
- Authorization Code grant 
  * the client first uses a web browser to navigate to a dedicated authorization endpoint on the AS, indicating which scopes it requires.
  * The AS then authenticates the user directly in the browser and asks for consent for the client access.
  * If the user agrees then the AS generates an authorization code and gives it to the client to exchange for an access token at the token endpoint.
- Client Credentials grant
  * client to obtain an access token using its own credentials, with no user involved at all.
  * This grant can be useful in some microservice communications patterns.
- Device authorization grant
  * Devices without any direct means of user interaction.
  
#### Discovering OAuth2 endpoints
-  If your AS is hosted as **https://as.example.com:8443**  then a GET request to **https://as.example.com:8443/.well-known/oauth-authorization-server**
   ```
   {
      "authorization_endpoint": "http://openam.example.com:8080/oauth2/authorize",
      "token_endpoint": "http://openam.example.com:8080/oauth2/access_token",
   }
   ```
   
### The Authorization Code grant
- By far the most useful and secure choice for most clients is the authorization code grant.

![](.README/bf1d274b.png)

![](.README/d612adba.png)

- Finally, the client should generate a unique random state value for each request and store it locally (such as in a browser cookie).
- When the AS redirects back to the client with the authorization code it will include the same state parameter, and the client should check that it matches the original one sent on the request.
- This ensures that the code received by the client is the one it requested. 
- The client can then exchange the authorization code for an access token by calling the token endpoint on the AS. It sends the authorization code in the body of a POST request, using the application/x-www-form-urlencoded encoding used for HTML forms.
  * Indicate the authorization code grant type is being used by including grant_ type=authorization_code.
  * Include the client ID in the client_id parameter or supply client credentials to identify the client.
  * Include the redirect URI that was used in the original request in the redirect _uri parameter.
  * Finally, include the authorization code as the value of the code parameter.
  
  ```
  POST /token HTTP/1.1
  Host: as.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic dGVzdDpwYXNzd29yZA==        **Supply client credentials for a confidential client.**
  grant_type=authorization_code
  &code=kdYfMS7H3sOO5y_sKhpdV6NFfik
  &redirect_uri=https://client.example.net/callback
  ```
- If the client is confidential, then it must authenticate to the token endpoint when it exchanges the authorization code.
- In the most common case, this is done by including the client ID and client secret as a username and password using HTTP Basic authentication, but alternative authentication methods are allowed, such as using a JWT or TLS client certificate.

#### Redirect URIs for different types of clients
- For a traditional web application, it’s simple to create a dedicated endpoint to use for the redirect URI to receive the authorization code.
- For a single-page app, the redirect URI should be the URI of the app from which client-side JavaScript can then extract the authorization code and make a CORS request to the token endpoint.
- For mobile applications, there are two primary options
  * The application can register a private-use URI scheme with the mobile operating system, such as myapp://callback. When the AS redirects to myapp://callback?code=... in the system web browser, the operating system will launch the native app and pass it the callback URI. The native application can then extract the authorization code from this URI and call the token endpoint.
    * A drawback with private-use URI schemes is that any app can register to handle any URI scheme, so a malicious application could register the same scheme as your legitimate client. 
  * An alternative is to register a portion of the path on the web domain of the app producer. For example, your app could register with the operating system that it will handle all requests to https://example.com/app/callback. When the AS redirects to this HTTPS endpoint, the mobile operating system will launch the native app just as for a private-use URI scheme. 
    * Android calls this an App Link (https://developer.android.com/training/app-links/)
    * iOS they are known as Universal Links (https://developer.apple.com/ios/universal-links/).
    
#### Hardening code exchange with PKCE
- Before the invention of claimed HTTPS redirect URIs, mobile applications using private-use URI schemes were vulnerable to code interception by a malicious app registering the same URI scheme.
- To protect against this attack, the OAuth working group developed the PKCE standard (Proof Key for Code Exchange), pronounced “pixy”.
##### Why PKCE ?
- For example, an attacker may be able to obtain a genuine authorization code by interacting with a legitimate client and then using an XSS attack against a victim to replace their authorization code with the attacker’s. Such an attack would be quite difficult to pull off but is theoretically possible. It’s therefore recommended that all types of clients use PKCE to strengthen the authorization code flow.
##### How PKCE works ?
- Before the client redirects the user to the authorization endpoint, it generates another random value, known as the **PKCE code verifier**.
- The client stores the code verifier locally, alongside the state parameter.
- Rather than sending this value directly to the AS, the client first hashes it using the SHA-256 cryptographic hash function to create a code challenge.
- The client then adds the code challenge as another query parameter when redirecting to the authorization endpoint.

![](.README/5825cb98.png)

- Later, when the client exchanges the authorization code at the token endpoint, it sends the original (unhashed) code verifier in the request.
- The AS will check that the SHA-256 hash of the code verifier matches the code challenge that it received in the authorization request.
- Authorization servers that don’t support PKCE should ignore the additional query parameters, because this is required by the OAuth2 standard.

#### Refresh tokens
- The refresh token is returned as another field in the JSON response from the token endpoint, as in the following example:
```
$ curl -d 'grant_type=password
➥ &scope=read_messages+post_message
➥ &username=demo&password=changeit'
➥ -u test:password
➥ https://as.example.com:8443/oauth2/access_token

{
  "access_token":"B9KbdZYwajmgVxr65SzL-z2Dt-4",
  "refresh_token":"sBac5bgCLCjWmtjQ8Weji2mCrbI",
  "scope":"post_message read_messages",
  "token_type":"Bearer","expires_in":3599
}
```

### Validating an access token
#### Token introspection
- To validate an access token using token introspection, you simply make a POST request to the introspection endpoint of the AS, passing in the access token as a parameter.

```
var form = "token=" + URLEncoder.encode(tokenId, UTF_8) + "&token_type_hint=access_token";

var httpRequest = HttpRequest.newBuilder()
            .uri(introspectionEndpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", authorization)
            .POST(BodyPublishers.ofString(form))
            .build();            
```

#### JWT access tokens
- Though token introspection solves the problem of how the API can determine if an access token is valid and the scope associated with that token, it has a downside: the API must make a call to the AS every time it needs to validate a token. 
- An alternative is to use a self-contained token format such as JWTs.
- To validate a JWT-based access token, the API needs to first authenticate the JWT using a cryptographic key. 

![](.README/291adbd3.png)

### OpenID Connect
- A standard way to retrieve identity information about a user, such as their name, email address, postal address, and telephone number.
  * The client can access a UserInfo endpoint to retrieve identity claims as JSON using an OAuth2 access token with standard OIDC scopes.
- OAuth2 is primarily a delegated access protocol, whereas OIDC provides a full authentication protocol. If the client needs to positively authenticate a user, then OIDC should be used. 
- Extensions for session management and logout, allowing clients to be notified when a user logs out of their session at the AS, enabling the user to log out of all clients at once (known as single logout). 

> In OIDC, the AS and RS are combined into a single entity known as an OpenID Provider (OP). The client is known as a Relying Party (RP).

#### ID tokens
- First, the client needs to call the authorization endpoint to get an authorization code.
- Then the client exchanges the code for an access token.
- Finally, the client can use the access token to call the UserInfo endpoint to retrieve the identity claims for the user.

![](.README/018c7b30.png)

- OIDC provides a way to return some of the identity and authentication claims about a user as a new type of token known as an ID token, which is a signed and optionally encrypted JWT.
- An ID token is a signed and optionally encrypted JWT that contains identity and authentication claims about a user.

- To validate an ID token, the client should first process the token as a JWT, decrypting it if necessary and verifying the signature.

#### Hardening OIDC
- FWD
#### Passing an ID token to an API
- FWD