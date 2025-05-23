<!-- Do not edit this file. It is automatically generated by API Documenter. -->

[Home](./index.md) &gt; [@codemonger-io/passquito-client-js](./passquito-client-js.md) &gt; [CredentialsApi](./passquito-client-js.credentialsapi.md) &gt; [refreshTokens](./passquito-client-js.credentialsapi.refreshtokens.md)

## CredentialsApi.refreshTokens() method

> This API is provided as a beta preview for developers and may change based on feedback that we receive. Do not use this API in a production environment.
> 

Refreshes the Cognito tokens associated with a given refresh token.

**Signature:**

```typescript
refreshTokens(refreshToken: string): Promise<CognitoTokens | undefined>;
```

## Parameters

<table><thead><tr><th>

Parameter


</th><th>

Type


</th><th>

Description


</th></tr></thead>
<tbody><tr><td>

refreshToken


</td><td>

string


</td><td>


</td></tr>
</tbody></table>
**Returns:**

Promise&lt;[CognitoTokens](./passquito-client-js.cognitotokens.md) \| undefined&gt;

Refreshed Cognito tokens. `undefined` if the refresh token is invalid or expired.

