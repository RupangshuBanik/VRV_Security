# Python-Intern
Assignments - VRV Security
### 1. **Requests per IP**
- This section lists the number of requests made by each IP address.
  - `IP Address`: The IP address from which the requests originated.
  - `Request Count`: The total number of requests made by the IP address.
 

### 2. **Most Accessed Endpoint**
- This section identifies the endpoint (URL or resource path) that was accessed the most number of times.
  - `Endpoint`: The most frequently accessed resource.
  - `Access Count`: The number of times this endpoint was accessed.

### 3. **Suspicious Activity**
- This section flags IP addresses with suspicious behavior, such as excessive failed login attempts.
  - `IP Address`: The IP address exhibiting suspicious activity.
  - `Failed Login Count`: The total number of failed login attempts from the IP address.

---
### [**Log Analysis Results**]
1. **Count Requests per IP Address**:
   
    ```bash
        IP Address           Request Count
        192.168.1.1          69
        203.0.113.5          8
        198.51.100.23        8
        10.0.0.2             6
        192.168.1.100        5
    ```

  2. **Identify the Most Frequently Accessed Endpoint**:

     ```bash
        Most Frequently Accessed Endpoint:
        Endpoint              Access Count
        /home                 67
     ```
  3. **Detect Suspicious Activity**:

     ```bash
        Suspicious Activity Detected:
        IP Address           Failed Login Attempts
