# @codemonger-io/passquito-cdk-construct

[CDK Construct](https://docs.aws.amazon.com/cdk/v2/guide/constructs.html) for Passquito core resources.

## Getting started

### Installing the package

TBD: `@codemonger-io/passquito-cdk-construct` is not available on npm yet.

### Example

The `PassquitoCore` construct defines the core resources for Passquito.

```ts
import { Stack } from 'aws-cdk-lib';
import type { Construct } from 'constructs';

import { PassquitoCore } from '@codemonger-io/passquito-cdk-construct';

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id);

    const passquito = new PassquitoCore(this, 'Passquito');
  }
}
```

## Passquito core resources

TBD