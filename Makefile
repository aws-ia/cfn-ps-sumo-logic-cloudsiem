# Source directory for CloudFormation (CF) templates
SRC_DIR := ./templates

LAMBDA_DIR :=  $(SRC_DIR)/apps/sumo-aws-apps/sumologic-app-utils
LAMBDA_ZIP := $(LAMBDA_DIR)/src/lambda.zip
LAMBDA_DEST := $(LAMBDA_DIR)/sumo_app_utils.zip

# Bucket name
CF_VERSION := 2
AWS_REGION := us-east-1
BUCKET_PREFIX := sumologic-aws-security-solutions
BUCKET := $(BUCKET_PREFIX)-$(AWS_REGION)
S3_KEY_PREFIX := cfn-ps-sumo-logic-cloudsiem

# S3 Location
S3_TEMPLATES := s3://$(BUCKET)/$(S3_KEY_PREFIX)/templates

# Sync options (Add --exclude '*.zip' if you don't want to upload lambda)
AWS_PROFILE = prod
SYNC_OPTS := --delete --include "*.yaml" --exclude '.DS_Store' --exclude '*.sh' --exclude 'apps/*/test/*' --exclude '*/test/*'  --acl public-read --profile $(AWS_PROFILE)

all: package sync

test-sync:
	aws s3 sync $(SRC_DIR) $(S3_TEMPLATES) --dryrun $(SYNC_OPTS)

sync:
	aws s3 sync $(SRC_DIR) $(S3_TEMPLATES) $(SYNC_OPTS)

# Define the regions where you want to create S3 buckets.
BUCKET_REGIONS := us-east-2 us-west-1 us-west-2 ap-east-1 ap-south-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-northeast-1 ca-central-1 eu-central-1 eu-west-1 eu-west-2 eu-west-3 eu-north-1 me-south-1 sa-east-1

create-regional-buckets:
	@for region in $(BUCKET_REGIONS); do \
		echo "Creating Bucket: $(BUCKET_PREFIX)-$$region in $$region" ; \
		aws s3api create-bucket --bucket $(BUCKET_PREFIX)-$$region --region $$region --create-bucket-configuration LocationConstraint=$$region --profile $(AWS_PROFILE) ; \
		aws s3api put-public-access-block --bucket $(BUCKET_PREFIX)-$$region --region $$region --public-access-block-configuration 'BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false' --profile $(AWS_PROFILE) ; \
		aws s3api put-bucket-ownership-controls --bucket $(BUCKET_PREFIX)-$$region --ownership-controls 'Rules=[{ObjectOwnership="BucketOwnerPreferred"}]' --profile $(AWS_PROFILE) ; \
	done

#  By default sync command does not delete files that exist in the destination but not in the source. Use the --delete option. Exclude the Source Bucket region from BUCKET_REGIONS before running sync command. If the file does not change then the ACL won't be changed, you will have to delete and sync again.
sync-regional-buckets:
	@for region in $(BUCKET_REGIONS); do \
		echo "Copying folder from Source Bucket: $(BUCKET) in $(AWS_REGION) region to Destination Bucket: $(BUCKET_PREFIX)-$$region in $$region region" ; \
		aws s3 sync s3://$(BUCKET)/$(S3_KEY_PREFIX) s3://$(BUCKET_PREFIX)-$$region/$(S3_KEY_PREFIX) --source-region $(AWS_REGION) --region $$region --delete --acl public-read --profile $(AWS_PROFILE); \
	done

package:
	taskcat package -s $(LAMBDA_DIR) -z $(LAMBDA_DIR)
	mv $(LAMBDA_ZIP) $(LAMBDA_DEST)

.PHONY: sync package test-sync create-regional-buckets sync-regional-buckets
