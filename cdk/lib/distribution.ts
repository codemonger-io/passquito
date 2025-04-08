import {
  Fn,
  RemovalPolicy,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_s3 as s3,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

import type { CredentialsApi } from '@codemonger-io/passquito-cdk-construct';

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

    const { appBasePath, credentialsApi } = props;

    const appIndex = appBasePath.replace(/\/$/, '') + '/index.html';

    // S3 buckets for the app contents
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
      additionalBehaviors: {
        [`${credentialsApi.basePath}/*`]: {
          origin: new origins.HttpOrigin(
            Fn.parseDomainName(credentialsApi.credentialsApi.url),
          ),
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          // deals with only POST requests
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
          // CORS is unnecessary because the app resides in the same domain
        },
      },
      errorResponses: [
        // redirects to the app index whenever access is denied
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: appIndex,
        },
      ],
      enableLogging: true,
    });
  }

  /** URL of the app. */
  get appUrl(): string {
    const appIndex = this.props.appBasePath
      .replace(/\/$/, '')
      .replace(/^\//, '');
    return `https://${this.distribution.domainName}/${appIndex}/`;
  }
}
