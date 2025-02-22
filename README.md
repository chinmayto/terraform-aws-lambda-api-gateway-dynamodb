# Deploying a REST API using API Gateway, Lambda, DynamoDB, and Terraform

In this tutorial, we aim to build a hands-on project that is versatile and applicable in various real-world scenarios, especially in today's landscape, where most applications follow a microservices architecture built with modular components.

Specifically, our objective is to create an API hosted on API Gateway, with AWS Lambda handling the backend logic and DynamoDB serving as the database. The Lambda function will implement CRUD operations (Create, Read, Update, Delete) on the DynamoDB table. This serverless architecture ensures scalability, cost-effectiveness, and ease of maintenance.


### Why API Gateway?
AWS API Gateway is a fully managed service that enables developers to create, publish, maintain, monitor, and secure APIs at any scale. It acts as a front-end for REST APIs and integrates seamlessly with backend services such as AWS Lambda, EC2, and DynamoDB. API Gateway provides features like request validation, transformation, authentication, rate limiting, and monitoring.

### Architecture
### Step 1: Create Lambda IAM Role
To enable Lambda to access DynamoDB with basic execution permissions, we need to define an IAM role with the necessary permissions.
```terraform
################################################################################
# Lambda IAM role to assume the role
################################################################################
resource "aws_iam_role" "lambda_role" {
  name = "lambda_execution_role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Principal" : {
        "Service" : "lambda.amazonaws.com"
      },
      "Action" : "sts:AssumeRole"
    }]
  })
}

################################################################################
# Create policy to acess the DynamoDB
################################################################################
resource "aws_iam_policy" "DynamoDBAccessPolicy" {
  name        = "DynamoDBAccessPolicy"
  description = "DynamoDBAccessPolicy"
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : [
            "dynamodb:List*",
            "dynamodb:DescribeReservedCapacity*",
            "dynamodb:DescribeLimits",
            "dynamodb:DescribeTimeToLive"
          ],
          "Resource" : "*",
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "dynamodb:BatchGet*",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTable",
            "dynamodb:Get*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchWrite*",
            "dynamodb:CreateTable",
            "dynamodb:Delete*",
            "dynamodb:Update*",
            "dynamodb:PutItem"
          ],
          "Resource" : [
            "arn:aws:dynamodb:*:*:table/Books_Table"  ## Name of the dynamoDB Table
          ],
          "Effect" : "Allow"
        }
      ]
    }
  )
}

################################################################################
# Assign policy to the role
################################################################################
resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda_basic_execution"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy_attachment" "lambda_dynamodb_access" {
  name       = "lambda_dynamodb_access"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = aws_iam_policy.DynamoDBAccessPolicy.arn
}
```
### Step 2: Setup lambda code
This Lambda function serves as the backend for a REST API, handling CRUD operations on a DynamoDB table. It integrates with API Gateway and follows best practices like structured logging, error handling, and efficient DynamoDB interactions. We are using AWS SDK for Python to interact with AWS services (DynamoDB in this case).

We have defined a method for each operation and return a response to the API Gateway, with different status codes. We will write the code of the function in Python.

```
import os
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
import logging
import json

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define API paths
book_path = '/book'
books_path = '/books'

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.getenv('DYNAMODB_TABLE'))

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    try: 
        http_method = event.get('httpMethod')
        path = event.get('path')
        # Handle GET Request - Fetch All Books
        if http_method == 'GET' and path == books_path:
            return get_all_books()
            
        # Handle GET Request - Fetch a Single Book
        elif http_method == 'GET' and path == book_path:
            params = event.get('queryStringParameters')
            if not params or 'book_id' not in params:
                return generate_response(400, 'Missing required parameter: book_id')

            return get_book(params['book_id'])
        
        # Handle POST Request - Save a New Book
        elif http_method == 'POST' and path == book_path:
            body = parse_request_body(event)
            if not body or 'book_id' not in body:
                return generate_response(400, 'Missing required field: book_id')
            
            return save_book(body)
            
        # Handle PATCH Request - Update a Book
        elif http_method == 'PATCH' and path == book_path:
            body = parse_request_body(event)
            if not body or 'book_id' not in body or 'update_key' not in body or 'update_value' not in body:
                return generate_response(400, 'Missing required fields: book_id, update_key, update_value')
            
            return update_book(body['book_id'], body['update_key'], body['update_value'])
            
        # Handle DELETE Request - Delete a Book
        elif http_method == 'DELETE':
            body = parse_request_body(event)
            if not body or 'book_id' not in body:
                return generate_response(400, 'Missing required field: book_id')
            
            return delete_book(body['book_id'])

        return generate_response(404, 'Resource Not Found')
                
    except ClientError as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return generate_response(500, 'Internal Server Error')

# Handle GET Request - Fetch a Single Book
def get_book(book_id):
    try:
        response = table.get_item(Key={'book_id': book_id})
        if 'Item' not in response:
            logger.warning(f"Book not found: {book_id}")
            return generate_response(404, f'Book with ID {book_id} not found')

        logger.info(f"GET book: {response['Item']}")
        return generate_response(200, response['Item'])

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error fetching book from database')

# Handle GET Request - Fetch All Books
def get_all_books():
    try:
        scan_params = {
            'TableName': table.name
        }
        items = recursive_scan(scan_params, [])
        logger.info('GET ALL items: {}'.format(items))
        return generate_response(200, items)
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error fetching books from database')

# Recursive function to scan all items in DynamoDB table    
def recursive_scan(scan_params, items):
    response = table.scan(**scan_params)
    items += response['Items']
    if 'LastEvaluatedKey' in response:
        scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
        recursive_scan(scan_params, items)
    return items

# Handle POST Request - Save a New Book
def save_book(item):
    try:
        response = table.put_item(Item=item)
        return generate_response(201, {'Message': 'Book saved successfully', 'Item': item})

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error saving book')
    
# Handle PATCH Request - Update a Book    
def update_book(book_id, update_key, update_value):
    try:
        response = table.update_item(
            Key={'book_id': book_id},
            UpdateExpression=f'SET {update_key} = :value',
            ExpressionAttributeValues={':value': update_value},
            ConditionExpression='attribute_exists(book_id)',  # Ensure item exists
            ReturnValues='UPDATED_NEW'
        )
        return generate_response(200, {'Message': 'Book updated successfully', 'UpdatedAttributes': response['Attributes']})

    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Update failed: Book with ID {book_id} does not exist")
            return generate_response(404, f'Book with ID {book_id} not found')
        
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error updating book')
    
# Handle DELETE Request - Delete a Book    
def delete_book(book_id):
    try:
        response = table.delete_item(
            Key={'book_id': book_id},
            ReturnValues='ALL_OLD'
        )
        if 'Attributes' not in response:
            return generate_response(404, f'Book with ID {book_id} not found')

        return generate_response(200, {'Message': 'Book deleted successfully', 'DeletedItem': response['Attributes']})

    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
        return generate_response(500, 'Error deleting book')

# Helper functions - Parse Request Body and Generate Response
def parse_request_body(event):
    try:
        return json.loads(event.get('body', '{}'))
    except json.JSONDecodeError:
        return None

# Custom JSON Encoder to handle Decimal types
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Generate API response
def generate_response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'status': status_code, 'data': body}, cls=DecimalEncoder)
    }
```
### Step 3: Create a Lambda Function using the code
Archive the python code and deploy a lambda function.
```terraform
################################################################################
# Compressing lambda function code
################################################################################
data "archive_file" "lambda_function_archive" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

################################################################################
# Creating Lambda Function
################################################################################
resource "aws_lambda_function" "book_lambda_function" {
  function_name = "Books_Lambda"
  filename      = "${path.module}/lambda_function.zip"

  runtime = "python3.12"
  handler = "lambda_function.lambda_handler"
  memory_size = 128
  timeout     = 10

  environment {
    variables = {
      DYNAMODB_TABLE = "Books_Table"
    }
  }

  source_code_hash = data.archive_file.lambda_function_archive.output_base64sha256

  role = aws_iam_role.lambda_role.arn
}

################################################################################
# Creating CloudWatch Log group for Lambda Function
################################################################################
resource "aws_cloudwatch_log_group" "book_lambda_function_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.book_lambda_function.function_name}"
  retention_in_days = 30
}
```

### Step 3: Setup DynamoDB Table
Create a DynamoDB table for storing book records. And create sample records from books.json

```terraform
################################################################################
# Creating DynamoDB table
################################################################################
resource "aws_dynamodb_table" "books_table" {
  name           = "Books_Table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "book_id"

  attribute {
    name = "book_id"
    type = "S"
  }
}

################################################################################
# Creating DynamoDB table items
################################################################################
locals {
  json_data = file("${path.module}/books.json")
  books     = jsondecode(local.json_data)
}

resource "aws_dynamodb_table_item" "books" {
  for_each   = local.books
  table_name = aws_dynamodb_table.books_table.name
  hash_key   = aws_dynamodb_table.books_table.hash_key
  item       = jsonencode(each.value)
}
```
### Step 4: Setup API Gateway
The API Gateway functions as a proxy, forwarding incoming HTTP requests from the client to the Lambda function using a POST request.

First, we configure the API Gateway REST API and define two API resources, one for each path: /books and /book.

```terraform
################################################################################
# API gateway
################################################################################
resource "aws_api_gateway_rest_api" "API-gw" {
  name        = "lambda_rest_api"
  description = "This is the REST API for Best Books"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

################################################################################
# API resource for the path "/book"
################################################################################
resource "aws_api_gateway_resource" "API-resource-book" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  parent_id   = aws_api_gateway_rest_api.API-gw.root_resource_id
  path_part   = "book"
}

################################################################################
# API resource for the path "/books"
################################################################################
resource "aws_api_gateway_resource" "API-resource-books" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  parent_id   = aws_api_gateway_rest_api.API-gw.root_resource_id
  path_part   = "books"
}
```

We want following API endpoints or Methods:

GET /books: Retrieve the list of all books.
GET /book/{book_id}: Retrieve details of a specific book by its id.
POST /book: Add a new book to the database.
PATCH /book/{book_id}: Update the details of a specific book using its id.
DELETE /book/{book_id}: Delete a book from the database using its id.

To implement each HTTP method, we configure the following components:

`Method Request`: Defines the HTTP method (GET, POST, PATCH, DELETE) for the API Gateway.
`Integration Request`: Connects the API Gateway to the Lambda function, allowing it to process requests.
`Integration Response`: Defines how the Lambda function's response is processed and returned to the client.
`Method Response`: Specifies the response format and headers expected from the API Gateway.

Each `HTTP method request` (GET, POST, PATCH, DELETE) defined on a resource needs an `integration request`, which determines where the incoming requests should be sent for processing. In our case, the integration is set up to forward requests to an AWS Lambda function using "AWS_PROXY" as the integration type, API Gateway acts as a direct pass-through to the Lambda function. This means:
1. API Gateway forwards the entire request (headers, body, parameters) directly to Lambda.
2. API Gateway does not perform any transformation on the request—it simply invokes the Lambda function using an internal AWS API call.
3. The Lambda function must return a properly formatted response, including the status code, headers, and body. API Gateway directly relays this response back to the client.

The `Integration Response` controls how API Gateway processes the response received from the backend service (Lambda, HTTP service, or other integrations) before forwarding it to the client. It includes:
1. Mapping Status Codes: API Gateway can map backend responses (like a Lambda response) to predefined HTTP status codes in the Method Response. For example, if a Lambda function returns {"error": "Not Found"}, API Gateway can map it to a 404 Not Found status.
2. Header Mapping: Allows modification of response headers before sending them to the client.
3. Body Mapping Templates: In non-proxy integrations, API Gateway can transform the response payload into a different format using mapping templates.

The `Method Response` defines how API Gateway formats and presents the response to the client. It includes:
1. Status Codes: Specifies the possible HTTP response codes (e.g., 200 OK, 400 Bad Request, 500 Internal Server Error).
2. Response Headers: Determines the headers that should be included in the response, such as Content-Type or Access-Control-Allow-Origin (for CORS).

```terraform
################################################################################
## GET /book/{bookId}
################################################################################

resource "aws_api_gateway_method" "GET_one_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "GET_one_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gw.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.GET_one_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "GET_one_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.GET_one_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "GET_one_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.GET_one_method.http_method
  status_code = aws_api_gateway_method_response.GET_one_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.GET_one_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": $input.path('$.statusCode'),
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## GET ALL /books 
################################################################################

resource "aws_api_gateway_method" "GET_all_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  resource_id   = aws_api_gateway_resource.API-resource-books.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "GET_all_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gw.id
  resource_id             = aws_api_gateway_resource.API-resource-books.id
  http_method             = aws_api_gateway_method.GET_all_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "GET_all_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-books.id
  http_method = aws_api_gateway_method.GET_all_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "GET_all_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-books.id
  http_method = aws_api_gateway_method.GET_all_method.http_method
  status_code = aws_api_gateway_method_response.GET_all_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.GET_all_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## POST /book
################################################################################

resource "aws_api_gateway_method" "POST_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "POST_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gw.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.POST_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "POST_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.POST_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
}

resource "aws_api_gateway_integration_response" "POST_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.POST_method.http_method
  status_code = aws_api_gateway_method_response.POST_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.POST_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## PATCH /book
################################################################################

resource "aws_api_gateway_method" "PATCH_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "PATCH"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "PATCH_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gw.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.PATCH_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "PATCH_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.PATCH_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "PATCH_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.PATCH_method.http_method
  status_code = aws_api_gateway_method_response.PATCH_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.PATCH_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}

################################################################################
## DELETE /book
################################################################################

resource "aws_api_gateway_method" "DELETE_method" {
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  resource_id   = aws_api_gateway_resource.API-resource-book.id
  http_method   = "DELETE"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "DELETE_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.API-gw.id
  resource_id             = aws_api_gateway_resource.API-resource-book.id
  http_method             = aws_api_gateway_method.DELETE_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.book_lambda_function.invoke_arn
}

resource "aws_api_gateway_method_response" "DELETE_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.DELETE_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "DELETE_integration_response_200" {
  rest_api_id = aws_api_gateway_rest_api.API-gw.id
  resource_id = aws_api_gateway_resource.API-resource-book.id
  http_method = aws_api_gateway_method.DELETE_method.http_method
  status_code = aws_api_gateway_method_response.DELETE_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.DELETE_lambda_integration]

  response_templates = {
    "application/json" = <<EOF
    #set($inputRoot = $input.path('$.body'))
    {
      \"statusCode\": 200,
      \"body\": $inputRoot,
      \"headers\": {
        \"Content-Type\": \"application/json\"
      }
    }
    EOF
  }
}
```

Allow the API gateway to invoke the Lambda Function.
```terraform

################################################################################
# Setup Lambda permission to allow API Gateway to invoke the Lambda function
################################################################################
resource "aws_lambda_permission" "allow_api_gateway_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.book_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.API-gw.execution_arn}/*/*"
}

```

Next we create the deployment and a stage

```terraform
################################################################################
# Deployment of the API Gateway
################################################################################
resource "aws_api_gateway_deployment" "example" {

  depends_on = [
    aws_api_gateway_integration.GET_one_lambda_integration,
    aws_api_gateway_integration.GET_all_lambda_integration,
    aws_api_gateway_integration.PATCH_lambda_integration,
    aws_api_gateway_integration.POST_lambda_integration,
    aws_api_gateway_integration.DELETE_lambda_integration
  ]

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.API-resource-book,
      aws_api_gateway_method.GET_one_method,
      aws_api_gateway_integration.GET_one_lambda_integration,
      aws_api_gateway_method.GET_all_method,
      aws_api_gateway_integration.GET_all_lambda_integration,
      aws_api_gateway_method.POST_method,
      aws_api_gateway_integration.POST_lambda_integration,
      aws_api_gateway_method.PATCH_method,
      aws_api_gateway_integration.PATCH_lambda_integration,
      aws_api_gateway_method.DELETE_method,
      aws_api_gateway_integration.DELETE_lambda_integration
    ]))
  }

  rest_api_id = aws_api_gateway_rest_api.API-gw.id
}

################################################################################
# Create a stage for the API Gateway
################################################################################
resource "aws_api_gateway_stage" "my-prod-stage" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.API-gw.id
  stage_name    = "prod"
}
```

Enable cloudwatch logging for API Gateway

### Conclusion

This demonstrates how to build a fully serverless, scalable, and cost-effective RESTful API for book management using AWS Lambda, API Gateway, and DynamoDB, with Terraform for automated infrastructure provisioning. It follows best practices for API design, response handling, and infrastructure as code, making it an ideal approach for cloud-native applications. Although, it doesnt include facility to authorize the requests as APIs can be triggered by anyone having the url, therefore we will explore authorization techniques in upcoming blogs!

### References
GitHub Repo:
