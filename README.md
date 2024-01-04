# HashiCorp Vault - Unauthenticated Memory Secrets Extraction
Proof of concept to extract secrets when HashiCorp Vault is unsealed.

![Vault_VerticalLogo_FullColor](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/e039395c-182d-489e-a4ca-a0cd6f34b326)

### Caching and Storing Mechanisms

#### In-memory Data

When we refer to the **HashiCorp Vault** documentation, we observe under which conditions it stores all information in memory:

According to the documentation, it's strongly advised against using a server in development mode within a production environment, as all information is handled in memory. However, it's noteworthy that despite this, the information is still encrypted—a crucial aspect preventing unauthorized access to secrets and sensitive data.

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/3f149f06-48e2-4c9c-bf0a-b72e7af834d8)

##### [Image retrieved from Hashicorp Vault - Starting the Server](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-dev-server)

On another note, we have the caching topic: 
![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/135a0aa7-0cdd-4447-b832-bb14f70221a0)

##### [Image retrieved from Hashicorp Vault - Vault Agent Caching](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching)

The issue with those *Tokens* and *Leases* that are *Cached* in-memory is that they store sensitive information and secrets (unencrypted) that could be used to compromise other services, for instance, Active Directory Domain Services (LDAP - Auth Method).

#### Persistent Cache

**Vault** can create/maintain persistent cache through a file (This setting needs to be specified in the **Vault server** *configuration file*):

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/120c7a36-9e4b-4941-95ca-ae1c4e8a215e)

##### [Image retrieved from Hashicorp Vault - Vault Agent Persistent Caching](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/caching/persistent-caches)

Here is a sample configuration for **Vault** to have persistent *cache*:

```
cache {
  persist "kubernetes" {
    path = "/vault/agent-cache"
  }
}
```

### HashiCorp Vault - Unaunthenticated Secrets Extraction

In the following scenario, **Vault** is set up for a *production environment* and employs **LDAPS** as its authentication mechanism.

Next, we have the **Vault** configuration file:

* **Note:** Please note in the configuration details that a *persistent cache* is not implemented at any point.
  
```
storage "raft" {
  path    = "./vault/data"
  node_id = "node1"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true
```
##### LDAP Authentication - Groups and users allowed to authenticate

As shown in the next figures, the *VaultAdm* group includes the user *Tony Stark (tstark)*, who is granted access to **Vault** using **LDAPS** authentication:

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/1583713f-dd30-41ff-8d2a-1c88deb51a59)

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/7aa02f1f-950f-4c6c-bec2-5139828ff40b)

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/1257feea-6afd-4648-86ef-49261deed6b7)

##### LDAP Authentication - Leases

The following *leases* are the result of multiple successful authentications against **Vault**:

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/06a4c976-8ee3-4f1d-86dc-1eb4dbb3ca08)

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/a8193ad7-ce2e-49c4-80c5-923d98c47fe8)

It's crucial to emphasize that sensitive information from *leases*, such as credentials, is **never visible**. Only informative details, such as *TTL*, *Expiration time*, *Expires In*, and *Issue Time*, are *available*.

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/6e1c606a-295a-4864-b0be-c93d9b1eee70)


#### Vulnerability Exploitation Pt.1:

First of all, we'll commence a new **Vault** process in *production mode:*

![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/3490d4c4-9d49-4d05-bb5e-b3da4139c21e)

A  vulnerability was observed wherein, upon **Vault** unseal, without user authentication, access to **Vault's memory** allows for *extraction of unencrypted secrets and leases*:

  1. Upon initiating a new **Vault** process, it will be **sealed by default**. We can verify this by using the *'vault status'* command or by making an HTTP GET request to the **'/sys/seal-status'** API endpoint:
     
     > vault status 

       ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/ef99914e-aefe-46b3-bd97-9e7a8c7fb027)

  2. Unsealing the Vault by providing the Keys:
     
      The *'vault operator unseal'* command will be repeated a total of **three (3) times**, which corresponds to the minimum threshold required to unlock **Vault**:
     
     > vault operator unseal

       ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/ff6dd378-8133-4c6b-b181-0192606d6408)

      **IMPORTANT:** At this point, we've merely **unsealed Vault**, but *we haven't authenticated against **Vault***. Therefore, we can't interact with the system (For instance, viewing secret engines, authentication methods, mounting new secret engines, etc.) as *we don't yet possess a valid token (**Vault**'s core authentication mechanism)*.

  3. Nevertheless, the vulnerability lies in the fact that when a new **Vault** process starts and is *unsealead*, it becomes possible to access the process's memory and retrieve the leases associated with a user. This can lead to the **extraction of clear-text credentials, along with relevant information tied to the token**:

     As a *proof of concept*, we can employ an utility (e.g., **Process Hacker**) that analyzes the **virtual memory space** of a process and searches for a *pattern* that provides the sensitive information we seek—in this case, **clear-text credentials** and information related to a **token** within the **Vault** process:
     
  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/6bcb9687-6380-4571-826a-2f217648bc0a)

  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/bdd9d5d7-6000-41cb-a01e-93241b6c7e69)

  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/93f62a28-5fef-428b-a75c-57970d8004c7)

  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/3eeca147-638a-4134-8ef7-24df522edb49)

  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/e5d6dce6-a0ce-4c84-990a-6b0c37bd7e68)

  The next step is crucial because it's where we specify the *pattern* we'll search for within the process memory. For instance, we might choose a pattern like **auth/ldap/login**:
  
  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/5150e42b-c26e-4bb7-a3c7-093e60d651ac)

  Let's take one of the *leases* and copy the details it retains:

  ![image](https://github.com/CarlosG13/HashiCorp-Vault---Unauthenticated-Memory-Secrets-Extraction/assets/69405457/44b69864-d709-4488-bb6c-004ced73d17f)

 Here are the details of one of the obtained tstark's *leases*:

> 0xc0032ba000 (1175): {"lease_id":"auth/ldap/login/tstark/h8cf7ce4b822d86169284e492c489cf2d3c4e8c39c8a4711ca1831c838185f362","client_token":"hvs.yWGUR4575KFItXCa9wDTtLpH","token_type":0,"path":"auth/ldap/login/tstark","data":null,"secret":null,"auth":{"lease":2764800000000000,"max_ttl":0,"renewable":true,"internal_data":{"password":"password123!"},"display_name":"ldap-tstark","policies":["vaultpol"],"token_policies":["default","vaultpol"],"identity_policies":null,"external_namespace_policies":null,"no_default_policy":false,"metadata":{"username":"tstark"},"client_token":"hvs.yWGUR4575KFItXCa9wDTtLpH","accessor":"nr4U43e8fcNRszPktlTYWhyW","period":0,"explicit_max_ttl":0,"num_uses":0,"entity_id":"25d9c5bf-9e9a-1d22-ba18-547fc70a743c","alias":{"mount_type":"ldap","mount_accessor":"auth_ldap_f7989ea9","name":"tstark","metadata":{"name":"tstark"}},"group_aliases":null,"bound_cidrs":null,"creation_path":"","token_type":1,"orphan":true,"policy_results":null,"mfa_requirement":null,"entity_created":false},"issue_time":"2023-12-20T05:54:03.4148106-08:00","expire_time":"2024-01-21T05:54:03.4148106-08:00","last_renewal_time":"0001-01-01T00:00:00Z","login_role":"","version":1,"revokeErr":""}

Within the information disclosed by the *lease*, notable details include the **client token**, **plaintext password** of the user for authentication against the **domain controller (Active Directory Domain Services)**, **token type**, **token policies**, **TTL**, and more. As a result, an unauthorized actor can access **Vault** leveraging the **client's token**. However, it's crucial to note that due to this *condition/vulnerability*, it's possible to compromise another service, in this case, **Active Directory Domain Services**, as *user credentials are provided in plaintext*. This can lead to a complete compromise of the **Active Directory environment** if the user is an *administrator*.

It's important to highlight the following points:

  1. All of this was done from the perspective of not being authenticated against **Vault**.
     
  2. According to calculations and multiple tests conducted against **Vault**, the attacker has a window of approximately five (5) minutes to exploit this vulnerability and steal the process credentials when **Vault** is *unsealed*. However, *this time frame provides sufficient leeway to carry out the attack*.

#### Vulnerability Exploitation Pt.2 - Instrumentation and attack path:

To attack **Vault** and steal the *leases's sensitive information*, an attacker may develop a **malicious artifact** with the following conditions:

  1. Constantly check the status of **Vault** to see if it's **unsealed**. This poses no issue as, without authentication, we can check such status as previously mentioned via an HTTP GET Request to **'/sys/seal-status'**.

     Knowing that to exploit this condition/vulnerability, the attack vector **(AV)** is **LOCAL**, the attacker has multiple alternatives to force the **unsealing** process:

      1.1. **Terminate** the **Vault** process and **restart** it, thereby waiting for administrators to **unseal** it.

      1.2. An attacker who has obtained **unsealing keys** (which is quite possible, as in my experience conducting adversary         emulations and penetration tests, many administrators place all keys in insecure locations, for instance, shared SMB folders).
  
  2. Then, once **Vault** has been **unsealed**, proceed with reading the memory of the concerned process. Multiple methods can be employed to achieve this goal; here's a potential procedure (**exploiting the vulnerability isn't limited to this**, other functions and techniques can be leveraged):

        * Use **OpenProcess** to obtain a valid handle for reading **Vault**'s virtual memory.
        * Use **ReadProcessMemory** to read Vault's virtual memory space in chunks.
        * Use **NtAccessCheckAndAuditAlarm** to determine if a specific memory address is valid or not.


