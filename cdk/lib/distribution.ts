import {
  RemovalPolicy,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

import type { CredentialsApi } from './credentials-api';

/** Props for `Distribution`. */
export interface DistributionProps {
  /** Base path of the app. */
  readonly appBasePath: string;
  /** Credentials API. */
  readonly credentialsApi: CredentialsApi;
}

/**
 * CDK construct that provisions the CloudFront distribution that serves both
 * the app and credentials API.
 */
export class Distribution extends Construct {
  /** S3 bucket for the app contents. */
  readonly appBucket: s3.Bucket;
  /** CloudFront distribution. */
  readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, readonly props: DistributionProps) {
    super(scope, id);

    const appIndex = props.appBasePath.replace(/\/$/, '/index.html');

    this.appBucket = new s3.Bucket(this, 'AppBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: 'Passkey Test distribution',
      defaultBehavior: {
        origin: new origins.S3Origin(this.appBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      },
      errorResponses: [
        // redirects to the app index whenever a resource is not found
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: appIndex,
        },
      ],
      enableLogging: true,
    });
  }

  /** URL of the app for internal tests. */
  get appInternalUrl(): string {
    const appIndex = this.props.appBasePath
      .replace(/\/$/, '/index.html')
      .replace(/^\//, '');
    return `https://${this.distribution.domainName}/${appIndex}`;
  }
}
