package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/cenkalti/backoff/v4"
	fb "github.com/huandu/facebook/v2"
	"go.uber.org/zap"
)

// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/setting-up.html

func getSecret() {
	secretName := "Demo/ACCESS_TOKENS"
	region := "ap-south-1"

	//Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	//log.Println(fmt.Sprintf("SECRETS %s, error=%s", result, err))

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
			return
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
	}
	//log.Println(fmt.Sprintf("SECRETS %s, error=%s", reflect.TypeOf(secretString), decodedBinarySecret))
	log.Println(fmt.Sprintf("SECRETS %s, error=%s", secretString, decodedBinarySecret))

	// Your code goes here.
}

//const fbGroupID = "1488511748129645"
const fbGroupID = "486336649016230"

var whoamiHeaderVal = GetEnv("WHOAMI", "")
var fbFeedParams = fb.Params{
	"fields": `
id,created_time,from,link,message,message_tags,name,object_id,permalink_url,properties,
shares,source,status_type,type,updated_time,reactions.summary(true){id,name,type},
comments.summary(true){id,attachment,comment_count,created_time,from,like_count,message,message_tags,parent}`,
	"limit": "100",
}

func retryNotifyFunc(err error, duration time.Duration) {
	log.Println(fmt.Sprintf("Queued for retry after %s, error=%s", duration, err))
}

func getFbAccessToken(fbApp *fb.App, logger *zap.Logger) string {
	getSecret()
	//secretString := getSecret()
	//logger.Warn(secretString)
	longAccessToken := GetEnv("FB_LONG_ACCESS_TOKEN", "")
	if longAccessToken == "" {
		shortAccessToken := GetEnv("FB_SHORT_ACCESS_TOKEN", "")
		if shortAccessToken == "" {
			return shortAccessToken
		}
		var err error
		longAccessToken, _, err = fbApp.ExchangeToken(shortAccessToken)
		if err != nil {
			logger.Warn("Failed exchanging short access token for long access token", zap.Error(err))
			return shortAccessToken
		}

		// Update env
		updateEnvFile("FB_LONG_ACCESS_TOKEN", longAccessToken)
		err = os.Setenv("FB_LONG_ACCESS_TOKEN", longAccessToken)
		if err != nil {
			logger.Warn("Unable to write FB long access token to env file", zap.Error(err))
		}
	}
	return longAccessToken
}

func getFacebookSession(logger *zap.Logger) (*fb.Session, error) {
	var fbApp = fb.New(GetEnv("FB_APP_ID", ""), GetEnv("FB_APP_SECRET", ""))
	fbApp.RedirectUri = "https://beta.lttkgp.com"
	sessionToken := getFbAccessToken(fbApp, logger)
	if sessionToken == "" {
		return nil, errors.New("neither short nor long access token present")
	}
	fbSession := fbApp.Session(sessionToken)
	fbSession.RFC3339Timestamps = true

	return fbSession, nil
}

// FetchLatestPosts bootstraps the DB with Facebook posts
func FetchLatestPosts(dynamoSession *dynamodb.DynamoDB, logger *zap.Logger) error {
	// Initialize Facebook session
	fbSession, err := getFacebookSession(logger)
	if err != nil {
		logger.Fatal("Unable to create Facebook session", zap.Error(err))
	}
	fbSession.Version = "v8.0"
	logger.Debug("Created Facebook session", zap.Any("fbSession", fbSession))

	// Keep count of parsed posts
	parsedCount := 0
	latestCheckThreshold := GetEnv("LATEST_CHECK_THRESHOLD", "300")
	maxParsedCount, err := strconv.Atoi(latestCheckThreshold)
	if err != nil {
		maxParsedCount = 300
	}

	// Configure exponential backoff for retries
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.MaxInterval = 24 * time.Hour

	// Fetch the first page of response
	var feedResp fb.Result
	err = backoff.RetryNotify(func() error {
		var fbError error
		feedResp, fbError = fbSession.Get(fmt.Sprintf("%s/feed", fbGroupID), fbFeedParams)
		return fbError
	}, exponentialBackoff, retryNotifyFunc)
	if err != nil {
		logger.Warn("Unable to schedule retry for feed fetch", zap.Error(err))
		return err
	}
	paging, err := feedResp.Paging(fbSession)
	if err != nil {
		logger.Warn("Feed result can't be used for paging", zap.Error(err))
		return err
	}

	// Iterate through page results
	for {
		// Iterate through posts in page
		for _, post := range paging.Data() {
			// Read keys
			var keyMetadata KeyMetadata
			err := post.Decode(&keyMetadata)
			if err != nil {
				logger.Error("Failed to decode key metadata from Facebook post", zap.Error(err))
				continue
			}
			logger.Debug("Extracted key metadata from Facebook post", zap.Object("keyMetadata", keyMetadata))

			postData := PostData{
				CreatedTime:  keyMetadata.CreatedTime,
				FacebookID:   keyMetadata.FacebookID,
				FacebookPost: post,
				IsParsed:     "false",
			}

			// Insert post to DB
			UpdateOrInsertPost(dynamoSession, postData, logger)
			parsedCount++
		}

		if parsedCount >= maxParsedCount {
			break
		}

		// Break on last page
		var noMore bool
		err := backoff.RetryNotify(func() error {
			var pagingError error
			noMore, pagingError = paging.Next()
			return pagingError
		}, exponentialBackoff, retryNotifyFunc)
		if err != nil {
			logger.Error("Failed paging through Facebook response", zap.Error(err))
			return err
		}
		if noMore {
			break
		}
	}

	return nil
}
