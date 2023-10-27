<script setup lang="ts">
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { ref } from 'vue';

import { userPoolClientId } from '../auth-config'; 

const cognitoClient = new CognitoIdentityProviderClient({
  region: 'ap-northeast-1',
});

const username = ref('');

const onSubmit = async () => {
  console.log('initiating user authentication', username.value);
  try {
    const challenge = await cognitoClient.send(new InitiateAuthCommand({
      ClientId: userPoolClientId,
      AuthFlow: 'CUSTOM_AUTH',
      AuthParameters: {
        USERNAME: username.value,
      },
    }));
    console.log('initiated user authentication', challenge);
    if (challenge.ChallengeName === 'CUSTOM_CHALLENGE') {
      // responds to the custom challenge
      const res = await cognitoClient.send(new RespondToAuthChallengeCommand({
        ClientId: userPoolClientId,
        ChallengeName: 'CUSTOM_CHALLENGE',
        ChallengeResponses: {
            USERNAME: username.value,
            ANSWER: JSON.stringify({ dummy: 'dummy' }),
        },
        Session: challenge.Session,
      }));
      console.log('authentication results:', res);
    } else {
      throw new Error(`unexpected challenge name: ${challenge.ChallengeName}`);
    }
  } catch (err) {
    console.error(err);
  }
}
</script>

<template>
  <main>
    <form @submit.prevent="onSubmit">
      <label>
        Username:
        <input
          name="username"
          v-model="username"
        >
      </label>
      <input type="submit" value="Sign In">
    </form>
  </main>
</template>