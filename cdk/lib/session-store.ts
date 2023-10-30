import { RemovalPolicy, aws_dynamodb as dynamodb } from 'aws-cdk-lib';
import { Construct } from 'constructs';

/** CDK construct that provisions the DynamoDB table for sessions. */
export class SessionStore extends Construct {
    /**
     * DynamoDB table that stores sessions.
     *
     * ## Keys and attributes
     *
     * - Partition key: `pk`
     * - No sort key
     * - Time to live attribute: `ttl`
     *
     * ### User registration session
     *
     * - `pk`: "registration#<session ID>"
     * - `ttl`: 60 seconds after the session was created
     * - `userId`: unique user ID
     * - `userInfo`:
     *     - `username`: unique username
     *     - `displayName`: display name
     * - `state`: serialized internal state
     */
    readonly sessionTable: dynamodb.TableV2;

    constructor(scope: Construct, id: string) {
        super(scope, id);

        this.sessionTable = new dynamodb.TableV2(this, 'SessionTable', {
            partitionKey: {
                name: 'pk',
                type: dynamodb.AttributeType.STRING,
            },
            timeToLiveAttribute: 'ttl',
            billing: dynamodb.Billing.provisioned({
                readCapacity: dynamodb.Capacity.fixed(1),
                writeCapacity: dynamodb.Capacity.autoscaled({
                    maxCapacity: 1,
                }),
            }),
            removalPolicy: RemovalPolicy.DESTROY,
        });
    }
}