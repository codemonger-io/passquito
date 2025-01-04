# Passquito

Fly with [Passkey](https://passkeys.dev) &times; [AWS Cognito](https://aws.amazon.com/cognito/) = Passquito!

A PoC on [passkey](https://passkeys.dev) authentication inspired by [`aws-samples/amazon-cognito-passwordless-auth`](https://github.com/aws-samples/amazon-cognito-passwordless-auth).

Features:
- [Rust](https://www.rust-lang.org) &times; [AWS Lambda](https://aws.amazon.com/lambda/) → Snappy cold start!
- [AWS Cognito](https://aws.amazon.com/cognito/) Lambda triggers
- &#x1F4A9; Ugly codebase

## Usage scenarios and some details

The usage scenarios consist of two major parts:
1. [Registration](#registration-scenarios)
2. [Authentication](#authentication-scenarios)

### Registration scenarios

The registration scenarios have two variations:
1. [Registration of a new user](#registration-of-a-new-user)
2. [Registration of a new device of an existing user](#registration-of-a-new-device-of-an-existing-user)

The following sections in [_Web Authentication: An API for accessing Public Key Credentials Level 3_](https://www.w3.org/TR/webauthn-3/) are recommended to read for better understanding of the scenarios:
- [1.2.1. Registration](https://www.w3.org/TR/webauthn-3/#sctn-usecase-registration)
- [1.3.1. Registration](https://www.w3.org/TR/webauthn-3/#sctn-sample-registration)

#### Registration of a new user

1. *Your app* provides a *form* for the *user* to sign up.

2. A *user* fills the *form* with the *username* and the *display name*.

   Neither the *username* nor the *display name* are necessarily unique.
   They are provided for the *user* to locate the *passkey* in *user*'s device.

3. The *user* hits the *sign up* button.

4. *Your app* POSTs the *username* and the *display name* to the *registration start endpoint* (`/registration/start`).

5. The *registration start endpoint* generates a unique ID for the *user* → the *user ID*.

6. The *registration start endpoint* creates a new *challenge*.

7. The *registration start endpoint* stores a new *registration session* in the *session store*.

   The *registration session* includes the following parameters:
   - *session ID*: the primary key
   - *user ID*
   - *username*
   - *display name*
   - *challenge*

8. The *registration start endpoint* returns the *session ID* and *public key creation options* which include the *challenge* to *your app*.

9. *Your app* initiates a public key creation with the *public key creation options*.

10. The *user* authorizes the public key creation.

11. *User's authenticator* creates a new key pair (a *private key* and a *public key*).

12. *User's authenticator* signs the *challenge* with the *private key* → the *signature*.

13. *User's authenticator* returns a *public key credential* which includes the *public key* and the *signature* to *your app*.

14. *Your app* POSTs the *session ID* and the *public key credential* to the *registration finish endpoint* (`/registration/finish`).

15. The *registration finish endpoint* pops the *registration session* associated with the *session ID* from the *session store*.

16. The *registration finish endpoint* verifies the *public key credential*.

    The following parameters are involved in the verification:
    - *challenge*
    - *public key*
    - *signature*

17. The *registration finish endpoint* creates a new *Cognito user* with the following attributes:
    - `username`: *user ID*
    - `preferred_username`: *username*
    - `name`: *display name*

    **The *Cognito user* is provided with a random password, which is confirmed upon creation; i.e., the *user* never faces it.**

18. The *registration finish endpoint* stores the *public key* along with the following parameters in the *credential store*:
    - *user ID*: the primary key
    - The *credential ID* of the *public key*: the primary key
    - The *sub* attribute of the *Cognito user*

19. The *registration finish endpoint* returns an empty OK response to *your app*.

Sequence diagram:

```mermaid
sequenceDiagram
    actor User
    participant Authenticator
    participant YourApp
    participant RegistrationStartEndpoint
    participant RegistrationFinishEndpoint
    participant SessionStore
    participant CredentialStore
    participant Cognito

    YourApp-)User: Provide the form
    User-)YourApp: Fill the form
    User-)YourApp: Hit the sign up button
    activate YourApp

    YourApp->>RegistrationStartEndpoint: POST /registration/start
    activate RegistrationStartEndpoint

    RegistrationStartEndpoint->>RegistrationStartEndpoint: Generate a user ID
    RegistrationStartEndpoint->>RegistrationStartEndpoint: Create a challenge
    RegistrationStartEndpoint->>SessionStore: Store a registration session
    activate SessionStore
    SessionStore-->>RegistrationStartEndpoint: Registration session
    deactivate SessionStore
    RegistrationStartEndpoint-->>YourApp: Session ID, public key creation options
    deactivate RegistrationStartEndpoint
    YourApp-)Authenticator: Initiate a public key creation
    activate Authenticator
    deactivate YourApp

    Authenticator-)User: Ask for the authorization
    User-)Authenticator: Authorize the public key creation
    Authenticator->>Authenticator: Create a new key pair
    Authenticator->>Authenticator: Sign the challenge
    Authenticator-)YourApp: Public key credential
    activate YourApp
    deactivate Authenticator

    YourApp->>RegistrationFinishEndpoint: POST /registration/finish
    activate RegistrationFinishEndpoint

    RegistrationFinishEndpoint->>SessionStore: Pop the registration session
    activate SessionStore
    SessionStore-->>RegistrationFinishEndpoint: Registration session
    deactivate SessionStore
    RegistrationFinishEndpoint->>RegistrationFinishEndpoint: Verify the public key credential
    RegistrationFinishEndpoint->>Cognito: Create a new Cognito user
    activate Cognito
    Cognito-->>RegistrationFinishEndpoint: Cognito user
    deactivate Cognito
    RegistrationFinishEndpoint->>CredentialStore: Store the public key
    activate CredentialStore
    CredentialStore-->>RegistrationFinishEndpoint: OK
    deactivate CredentialStore
    RegistrationFinishEndpoint-->>YourApp: OK
    deactivate RegistrationFinishEndpoint

    YourApp-)User: OK
    deactivate YourApp
```

#### Registration of a new device of an existing user

TBD

### Authentication scenarios

The authentication scenarios have two variations:
1. [Authentication with discoverable credentials](#authentication-with-discoverable-credentials)
2. [Authentication of a specific user](#authentication-of-a-specific-user)

#### Authentication with discoverable credentials

#### Authentication of a specific user

This is not precisely a passkey authentication, but a passwordless authentication.