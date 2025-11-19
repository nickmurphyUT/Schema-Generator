import os
import requests
from flask import Flask, request, jsonify, render_template_string, render_template
from dotenv import load_dotenv
from datetime import datetime, timedelta
from urllib.parse import quote
import threading
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
from datetime import timezone
import logging
import json
import certifi
from datetime import datetime
from dateutil import parser
from flask_cors import CORS
import uuid
import pytz

allowed_origins = [
    "https://www.prostore.localhost",
    "https://qa2.resideo.com",
    "https://www.hotfix.rde.resideo.com",
    "https://www.resideo.com",
    "https://firstalert-prod-preview.vercel.app"
]

# Load environment variables
load_dotenv()

# Shopify API credentials
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SCOPES = os.getenv(
    "SHOPIFY_SCOPES",
    "read_customers,write_orders,read_orders,read_own_subscription_contracts,write_own_subscription_contracts,manage_orders_information,read_orders,write_orders,read_discounts,write_discounts,read_shopify_payments_disputes",
)
ACCESS_TOKEN = "xxx"  # Store access token after OAuth


# Hardcoded Admin API credentials (ONLY FOR SERVER-SIDE USAGE)
SHOPIFY_ADMIN_ACCESS_TOKEN = "xxx"
SHOPIFY_API_VERSION = "2024-01"  # or current stable version

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=allowed_origins, supports_credentials=True)
import requests
import logging

def query_shopify_graphql(shop, access_token, query):
    """
    Function to send a GraphQL query to Shopify API
    """
    # Shopify GraphQL endpoint
    url = f"https://{shop}/admin/api/2023-01/graphql.json"  # Adjust API version if needed

    # Headers to include the access token for authentication
    headers = {
        "X-Shopify-Access-Token": access_token,
        "Content-Type": "application/json"
    }

    try:
        # Send the request to Shopify's GraphQL API
        response = requests.post(url, headers=headers, json={"query": query})

        # Check for errors in the response
        if response.status_code != 200:
            logging.error(f"GraphQL query failed with status {response.status_code}: {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}: {response.text}")

        # Log the response for debugging purposes
        logging.debug(f"GraphQL Response: {response.json()}")

        # Return the response as JSON
        return response.json()
    
    except requests.exceptions.RequestException as e:
        # Catch request-specific exceptions such as network issues, timeouts, etc.
        logging.error(f"Request failed: {str(e)}")
        raise Exception(f"Request failed: {str(e)}")
    
    except Exception as e:
        # Catch all other exceptions
        logging.error(f"An error occurred: {str(e)}")
        raise Exception(f"An error occurred: {str(e)}")


def query_shopify_graphql_webhook(shop, access_token, query, variables=None):
    """
    Function to send a GraphQL query to Shopify API for webhook-related requests.
    This function also accepts variables, which are necessary for mutations (like webhook creation).
    """
    # Shopify GraphQL endpoint
    url = f"https://{shop}/admin/api/2023-01/graphql.json"  # Adjust API version if necessary

    # Headers to include the access token for authentication
    headers = {
        "X-Shopify-Access-Token": access_token,
        "Content-Type": "application/json"
    }

    # Prepare the payload with query and variables
    payload = {
        "query": query
    }
    if variables:
        payload["variables"] = variables  # If variables are provided, include them in the payload

    # Send the request to Shopify's GraphQL API
    response = requests.post(url, headers=headers, json=payload)

    # Check for errors in the response
    if response.status_code != 200:
        raise Exception(f"GraphQL query failed with status {response.status_code}: {response.text}")

    # Return the response as JSON
    return response.json()
import requests

def query_shopify_graphql_webhookB(shop, access_token, query, variables=None):
    """
    Function to send a GraphQL query to Shopify API for webhook-related requests.
    This function also accepts variables, which are necessary for mutations (like webhook creation).
    """
    # Shopify GraphQL endpoint
    url = f"https://{shop}/admin/api/2023-01/graphql.json"  # Adjust API version if necessary

    # Headers to include the access token for authentication
    headers = {
        "X-Shopify-Access-Token": access_token,
        "Content-Type": "application/json"
    }

    # Prepare the payload with query and variables
    payload = {
        "query": query
    }
    if variables:
        payload["variables"] = variables  # If variables are provided, include them in the payload

    try:
        # Send the request to Shopify's GraphQL API
        response = requests.post(url, headers=headers, json=payload)

        # Check for errors in the response
        if response.status_code != 200:
            raise Exception(f"GraphQL query failed with status {response.status_code}: {response.text}")

        # Try parsing the response as JSON
        response_json = response.json()

        # Check if the response contains errors
        if "errors" in response_json:
            raise Exception(f"GraphQL errors: {response_json['errors']}")

        # If response is valid, return the JSON data
        return response_json

    except Exception as e:
        # Log any exception that occurs during the request
        app.logger.error(f"Error in query_shopify_graphql_webhook: {str(e)}")
        return {"error": str(e), "details": str(e)}  # Return a more readable error



@app.route("/")
def home():
    return "Shopify OAuth App is running!"

@app.route("/auth")
def authenticate():
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    auth_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={SHOPIFY_API_KEY}&"
        f"scope={SCOPES}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"state=secure_random_string"
    )
    return redirect(auth_url)


# ✅ Step 2: Handle Shopify OAuth callback and return access token
@app.route("/auth/callback")
def auth_callback():
    shop = request.args.get("shop")
    code = request.args.get("code")

    if not shop or not code:
        return jsonify({"error": "Invalid request"}), 400

    token_url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        "client_id": SHOPIFY_API_KEY,
        "client_secret": SHOPIFY_API_SECRET,
        "code": code,
    }
    response = requests.post(token_url, json=payload)

    if response.status_code != 200:
        return jsonify({"error": "Error retrieving access token"}), 400

    access_token = response.json().get("access_token")

    return jsonify(
        {
            "message": "Authorization successful",
            "shop": shop,
            "access_token": access_token,
        }
    )

@app.route("/customer/<customer_id>/create-subscription", methods=["POST"])
def create_subscription(customer_id):
    shop = request.args.get("shop")
    payment_method_id = request.args.get("payment_method_id")  # Get payment method ID as input
    
    if not shop or not ACCESS_TOKEN or not payment_method_id:
        return jsonify({"error": "Missing shop parameter, access token, or payment method ID"}), 400
    
    # Get the current date and time, then add one hour
    current_time = datetime.utcnow()  # Get current UTC time
    future_time = current_time + timedelta(hours=1)  # Add 1 hour to current time
    # Format it in ISO 8601 format with time (Shopify's expected format)
    formatted_time = future_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Use string formatting for the mutation query
    subscription_mutation = """
    mutation {
      subscriptionContractCreate(
        input: {
          customerId: "gid://shopify/Customer/%s",
          nextBillingDate: "%s",
          currencyCode: USD,
          contract: {
            note: "Note Attributes",
            status: ACTIVE,
            paymentMethodId: "gid://shopify/CustomerPaymentMethod/%s",  # Insert payment method ID here
            billingPolicy: {
              interval: WEEK,
              intervalCount: 1,
              minCycles: 3
            },
            deliveryPolicy: {
              interval: WEEK,
              intervalCount: 1
            },
            deliveryPrice: 0.00,
            deliveryMethod: {
              shipping: {
                address: {
                  firstName: "Nick",
                  lastName: "Murphy",
                  address1: "1353 South Glenmare Street",
                  address2: "#77",
                  city: "Salt Lake City",
                  province: "Utah",
                  country: "USA",
                  zip: "84105"
                }
              }
            }
          }
        }
      ) {
        draft {
          id
        }
        userErrors {
          field
          message
        }
      }
    }
    """ % (customer_id, formatted_time, payment_method_id)
    
    # Send GraphQL request to create subscription contract
    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_mutation)
        
        # Log the response for debugging
        print("Shopify API Response:", response)

        # Check if the response is None
        if response is None:
            return jsonify({"error": "Received a None response from Shopify API"}), 500

        # Check if the response contains user errors
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error creating subscription contract", "details": response["userErrors"]}), 400
        
        # Check if 'data' key exists in the response and contains the expected structure
        if "data" not in response or "subscriptionContractCreate" not in response["data"]:
            return jsonify({"error": "Invalid response structure", "details": response}), 400

        # Return the draft ID
        draft_id = response["data"]["subscriptionContractCreate"]["draft"]["id"]
        return jsonify({"message": "Subscription contract draft created", "draft_id": draft_id})
    
    except Exception as e:
        # Catch any exceptions and return an error message
        return jsonify({"error": str(e)}), 500

@app.route("/order/<order_id>/flag-chargeback", methods=["POST"])
def flag_chargeback_on_order(order_id):
    shop = request.args.get("shop")
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    try:
        # Step 1: Get the existing order data to retrieve current tags
        order_url = f"https://{shop}/admin/api/2024-01/orders/{order_id}.json"
        headers = {
            "X-Shopify-Access-Token": ACCESS_TOKEN,
            "Content-Type": "application/json"
        }
        order_response = requests.get(order_url, headers=headers)
        if order_response.status_code != 200:
            return jsonify({"error": "Failed to fetch order", "details": order_response.json()}), order_response.status_code

        order_data = order_response.json().get("order", {})
        existing_tags = order_data.get("tags", "")
        tags_list = [tag.strip() for tag in existing_tags.split(",") if tag.strip()]

        # Step 2: Update tags
        updated_tags = [tag for tag in tags_list if tag.lower() != "nochargeback"]
        if "chargebackError" not in updated_tags:
            updated_tags.append("chargebackError")

        # Step 3: Send updated tags back to Shopify
        update_payload = {
            "order": {
                "id": order_id,
                "tags": ", ".join(updated_tags)
            }
        }
        update_response = requests.put(order_url, headers=headers, json=update_payload)
        if update_response.status_code != 200:
            return jsonify({"error": "Failed to update order tags", "details": update_response.json()}), update_response.status_code

        return jsonify({
            "message": "Order tags updated successfully",
            "updated_tags": updated_tags
        })

    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

        
@app.route("/customer/<customer_id>/subscription-contracts", methods=["GET"])
def get_subscription_contracts(customer_id):
    shop = request.args.get("shop")
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400
    
    query = f"""
    query {{
      subscriptionContracts(first: 10, query: "customer:{customer_id}") {{
        edges {{
          node {{
            id
            createdAt
            status
            nextBillingDate
            customer {{
              firstName
              lastName
            }}
            billingPolicy {{
              interval
              intervalCount
            }}
            deliveryPolicy {{
              interval
              intervalCount
            }}
          }}
        }}
      }}
    }}
    """
    
    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error fetching subscription contracts", "details": response["userErrors"]}), 400
        if "data" not in response or not response["data"]["subscriptionContracts"]["edges"]:
            return jsonify({"error": "No subscription contracts found for this customer"}), 404
        
        contracts = response["data"]["subscriptionContracts"]["edges"]
        contract_data = [
            {
                "id": contract["node"]["id"],
                "createdAt": contract["node"]["createdAt"],
                "status": contract["node"]["status"],
                "nextBillingDate": contract["node"]["nextBillingDate"],
                "customer": contract["node"]["customer"],
                "billingPolicy": contract["node"]["billingPolicy"],
                "deliveryPolicy": contract["node"]["deliveryPolicy"]
            }
            for contract in contracts
        ]
        
        return jsonify({"subscription_contracts": contract_data})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/customer/<customer_id>/update-subscription", methods=["POST"])
def update_subscription(customer_id):
    shop = request.args.get("shop")
    
    # Get the parameters from the request body
    subscription_contract_id = request.json.get("subscription_contract_id")
    product_variant_id = request.json.get("product_variant_id")
    quantity = request.json.get("quantity")
    price = request.json.get("price")
    
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400
    
    if not subscription_contract_id or not product_variant_id or quantity is None or price is None:
        return jsonify({"error": "Missing required parameters"}), 400
    
    # Step 1: Create a draft for the subscription contract
    subscription_contract_update_mutation = """
    mutation {
      subscriptionContractUpdate(
        contractId: \"%s\"
      ) {
        draft {
          id
        }
        userErrors {
          field
          message
        }
      }
    }
    """ % subscription_contract_id
    
    try:
        # Send the mutation to update the subscription contract and create a draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_contract_update_mutation)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error creating draft for subscription contract", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionContractUpdate"]["draft"]:
            return jsonify({"error": "No draft returned in the response", "details": response}), 400
        
        # Get the draft ID from the response
        draft_id = response["data"]["subscriptionContractUpdate"]["draft"]["id"]

        # Step 2: Add the line to the draft (add product variant, price, quantity)
        subscription_draft_line_add_mutation = """
        mutation {
          subscriptionDraftLineAdd(
            draftId: \"%s\"
            input: {
              productVariantId: \"%s\"
              quantity: %d
              currentPrice: %f
            }
          ) {
            lineAdded {
              id
              quantity
              productId
              variantId
              variantImage {
                id
              }
              title
              variantTitle
              currentPrice {
                amount
                currencyCode
              }
              requiresShipping
              sku
              taxable
            }
            draft {
              id
            }
            userErrors {
              field
              message
              code
            }
          }
        }
        """ % (draft_id, product_variant_id, quantity, price)
        
        # Send the mutation to add a line to the draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_draft_line_add_mutation)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error adding line to subscription draft", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionDraftLineAdd"]["draft"]:
            return jsonify({"error": "No draft found after adding line", "details": response}), 400
        
        # Step 3: Commit the draft
        subscription_draft_commit_mutation = """
        mutation {
          subscriptionDraftCommit(draftId: \"%s\") {
            contract {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
        """ % draft_id
        
        # Send the mutation to commit the draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_draft_commit_mutation)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error committing the draft", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionDraftCommit"]["contract"]:
            return jsonify({"error": "No contract found after committing draft", "details": response}), 400
        
        # Return the contract ID of the committed draft
        contract_id = response["data"]["subscriptionDraftCommit"]["contract"]["id"]
        
        return jsonify({
            "message": "Subscription updated and committed successfully.",
            "contract_id": contract_id
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/customer/<customer_id>/add-line-to-subscription-draft", methods=["POST"])
def add_line_to_subscription_draft(customer_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    data = request.get_json()
    draft_id = data.get("draft_id")
    line_items = data.get("line_items", [])

    if not draft_id or not line_items:
        return jsonify({"error": "Missing draft ID or line items"}), 400

    results = []

    for item in line_items:
        product_variant_id = item.get("product_variant_id")
        quantity = item.get("quantity")
        price = item.get("price")
        line_item_attributes = item.get("line_item_attributes", [])
        order_note = data.get("order_note")  # Optional, shared across items

        if not product_variant_id or quantity is None or price is None:
            return jsonify({
                "error": "Missing required parameters in one of the line items",
                "item": item
            }), 400

        # Format custom attributes (key/value, not name/value)
        formatted_attrs = []
        for attr in line_item_attributes:
            key = attr.get("key") or attr.get("name")
            value = attr.get("value")
            if key is not None and value is not None:
                safe_key = str(key).replace('"', '\\"')
                safe_value = str(value).replace('"', '\\"')
                formatted_attrs.append('{ key: "%s", value: "%s" }' % (safe_key, safe_value))

        attributes_gql = ""
        if formatted_attrs:
            attributes_gql = "customAttributes: [%s],\n" % ", ".join(formatted_attrs)

        # Format order note safely
        order_note_gql = ""
        if order_note:
            safe_note = order_note.replace('"', '\\"').replace("\n", "\\n")
            order_note_gql = 'note: "%s",\n' % safe_note

        # Construct the mutation
        subscription_draft_line_add_mutation = """
        mutation {
          subscriptionDraftLineAdd(
            draftId: "%s" 
            input: {
              productVariantId: "%s" 
              quantity: %d 
              currentPrice: %f 
              %s%s
            }
          ) {
            lineAdded {
              id
              quantity
              productId
              variantId
              variantImage {
                id
              }
              title
              variantTitle
              currentPrice {
                amount
                currencyCode
              }
              requiresShipping
              sku
              taxable
            }
            draft {
              id
            }
            userErrors {
              field
              message
              code
            }
          }
        }
        """ % (draft_id, product_variant_id, quantity, price, attributes_gql, order_note_gql)

        try:
            response = query_shopify_graphql(shop, access_token, subscription_draft_line_add_mutation)

            if (
                "data" not in response or
                "subscriptionDraftLineAdd" not in response["data"] or
                response["data"]["subscriptionDraftLineAdd"].get("userErrors")
            ):
                return jsonify({
                    "error": "Failed to add line item",
                    "response": response
                }), 400

            results.append(response["data"]["subscriptionDraftLineAdd"])

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({
        "message": "All line items added successfully.",
        "results": results
    })



@app.route("/customer/<customer_id>/commit-subscription-draft", methods=["POST"])
def commit_subscription_draft(customer_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")
    draft_id = request.json.get("draft_id")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    if not draft_id:
        return jsonify({"error": "Missing draft_id parameter"}), 400

    # GraphQL mutation
    subscription_draft_commit_mutation = f"""
    mutation {{
      subscriptionDraftCommit(draftId: \"{draft_id}\") {{
        contract {{
          id
        }}
        userErrors {{
          field
          message
        }}
      }}
    }}
    """

    try:
        response = query_shopify_graphql(shop, access_token, subscription_draft_commit_mutation)

        if "userErrors" in response and response["userErrors"]:
            return jsonify({
                "error": "Error committing the subscription draft",
                "details": response["userErrors"]
            }), 400

        contract_data = response.get("data", {}).get("subscriptionDraftCommit", {}).get("contract")
        if not contract_data:
            return jsonify({
                "error": "No contract returned after committing draft",
                "details": response
            }), 400

        return jsonify({
            "message": "Subscription draft committed successfully.",
            "contract_id": contract_data.get("id")
        })

    except Exception as e:
        app.logger.error(f"Error committing subscription draft: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500



@app.route("/customer/<customer_id>/update-existing-subscription", methods=["POST"])
def update_existing_subscription(customer_id):
    shop = request.args.get("shop")
    
    # Get the parameters from the request body
    subscription_contract_id = request.json.get("subscription_contract_id")
    product_variant_id = request.json.get("product_variant_id")
    quantity = request.json.get("quantity")
    price = request.json.get("price")
    
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400
    
    if not subscription_contract_id or not product_variant_id or quantity is None or price is None:
        return jsonify({"error": "Missing required parameters"}), 400
    
    # Step 1: Create a draft for the subscription contract update using variables
    subscription_contract_update_mutation = """
    mutation subscriptionContractUpdate($contractId: ID!) {
      subscriptionContractUpdate(
        contractId: $contractId
      ) {
        draft {
          id
        }
        userErrors {
          field
          message
        }
      }
    }
    """
    
    variables = {
        "contractId": subscription_contract_id
    }
    
    try:
        # Send the mutation to update the subscription contract and create a draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query=subscription_contract_update_mutation, variables=variables)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error creating draft for subscription contract", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionContractUpdate"]["draft"]:
            return jsonify({"error": "No draft returned in the response", "details": response}), 400
        
        # Get the draft ID from the response
        draft_id = response["data"]["subscriptionContractUpdate"]["draft"]["id"]

        # Step 2: Add the product to the draft (add product variant, price, quantity) using variables
        subscription_draft_line_add_mutation = """
        mutation subscriptionDraftLineAdd($draftId: ID!, $productVariantId: ID!, $quantity: Int!, $price: Float!) {
          subscriptionDraftLineAdd(
            draftId: $draftId
            input: {
              productVariantId: $productVariantId
              quantity: $quantity
              currentPrice: $price
            }
          ) {
            lineAdded {
              id
              quantity
              productId
              variantId
              variantImage {
                id
              }
              title
              variantTitle
              currentPrice {
                amount
                currencyCode
              }
              requiresShipping
              sku
              taxable
            }
            draft {
              id
            }
            userErrors {
              field
              message
              code
            }
          }
        }
        """
        
        variables = {
            "draftId": draft_id,
            "productVariantId": product_variant_id,
            "quantity": quantity,
            "price": price
        }
        
        # Send the mutation to add a line to the draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query=subscription_draft_line_add_mutation, variables=variables)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error adding line to subscription draft", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionDraftLineAdd"]["draft"]:
            return jsonify({"error": "No draft found after adding line", "details": response}), 400
        
        # Step 3: Commit the updated draft using variables
        subscription_draft_commit_mutation = """
        mutation subscriptionDraftCommit($draftId: ID!) {
          subscriptionDraftCommit(draftId: $draftId) {
            contract {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
        """
        
        variables = {
            "draftId": draft_id
        }
        
        # Send the mutation to commit the draft
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query=subscription_draft_commit_mutation, variables=variables)
        
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error committing the draft", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionDraftCommit"]["contract"]:
            return jsonify({"error": "No contract found after committing draft", "details": response}), 400
        
        # Return the contract ID of the committed draft
        contract_id = response["data"]["subscriptionDraftCommit"]["contract"]["id"]
        
        return jsonify({
            "message": "Subscription updated and committed successfully.",
            "contract_id": contract_id
        })
    
    except Exception as e:
        # Catch any exceptions and return an error message
        return jsonify({"error": str(e)}), 500


@app.route("/customer/subscription-contracts", methods=["GET"])
def get_first_10_subscription_contracts():
    shop = request.args.get("shop")
    
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400
    
    # GraphQL query to get the first 10 subscription contracts
    query = """
    query {
      subscriptionContracts(first: 10) {
        edges {
          node {
            id
            createdAt
            status
            nextBillingDate
            customer {
              firstName
              lastName
            }
            billingPolicy {
              interval
              intervalCount
            }
            deliveryPolicy {
              interval
              intervalCount
            }
          }
        }
      }
    }
    """
    
    try:
        # Query the Shopify GraphQL API
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        
        # Handle potential errors in the response
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error fetching subscription contracts", "details": response["userErrors"]}), 400
        
        if "data" not in response or not response["data"]["subscriptionContracts"]["edges"]:
            return jsonify({"error": "No subscription contracts found"}), 404
        
        contracts = response["data"]["subscriptionContracts"]["edges"]
        
        # Extract relevant data from the response
        contract_data = [
            {
                "id": contract["node"]["id"],
                "createdAt": contract["node"]["createdAt"],
                "status": contract["node"]["status"],
                "nextBillingDate": contract["node"]["nextBillingDate"],
                "customer": contract["node"]["customer"],
                "billingPolicy": contract["node"]["billingPolicy"],
                "deliveryPolicy": contract["node"]["deliveryPolicy"]
            }
            for contract in contracts
        ]
        
        return jsonify({"subscription_contracts": contract_data})
    
    except Exception as e:
        # Return a 500 error in case of any issues
        return jsonify({"error": str(e)}), 500
        

from flask import request, jsonify
import uuid

@app.route("/<contract_id>/create-billing-attempt", methods=["POST"])
def create_billing_attempt(contract_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    # Format the contract GID
    formatted_contract_id = "gid://shopify/SubscriptionContract/{}".format(contract_id)

    # Step 1: Fetch the contract's nextBillingDate
    get_contract_query = """
    query {
      subscriptionContract(id: "%s") {
        id
        nextBillingDate
        status
      }
    }
    """ % formatted_contract_id

    try:
        contract_response = query_shopify_graphql(shop, access_token, get_contract_query)

        contract_data = contract_response.get("data", {}).get("subscriptionContract")
        if not contract_data:
            return jsonify({"error": "Subscription contract not found."}), 404

        if contract_data.get("status") == "EXPIRED":
            return jsonify({"error": "Cannot create billing attempt on expired contract."}), 400

        next_billing_date = contract_data.get("nextBillingDate")
        if not next_billing_date:
            return jsonify({"error": "No nextBillingDate available for this contract."}), 400

        # Step 2: Attempt to create a billing attempt using that exact date
        idempotency_key = str(uuid.uuid4())
        billing_mutation = """
        mutation {
          subscriptionBillingAttemptCreate(
            subscriptionContractId: "%s",
            subscriptionBillingAttemptInput: {
              billingCycleSelector: { date: "%s" },
              idempotencyKey: "%s"
            }
          ) {
            subscriptionBillingAttempt {
              id
              ready
            }
            userErrors {
              field
              message
            }
          }
        }
        """ % (formatted_contract_id, next_billing_date, idempotency_key)

        billing_response = query_shopify_graphql(shop, access_token, billing_mutation)
        attempt_data = billing_response.get("data", {}).get("subscriptionBillingAttemptCreate", {})

        user_errors = attempt_data.get("userErrors", [])
        if user_errors:
            return jsonify({
                "error": "Error creating subscription billing attempt",
                "details": user_errors
            }), 400

        billing_attempt = attempt_data.get("subscriptionBillingAttempt")
        if not billing_attempt:
            return jsonify({"error": "Billing attempt creation returned no data."}), 500

        return jsonify({
            "message": "Subscription billing attempt created successfully.",
            "billing_attempt_id": billing_attempt.get("id"),
            "ready": billing_attempt.get("ready"),
            "billing_date_used": next_billing_date
        })

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@app.route("/<contract_id>/getTransactionInfo", methods=["POST"])
def get_transaction_info(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    # If token comes prefixed like "Bearer XYZ", strip the prefix
    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    contract_gid = "gid://shopify/SubscriptionContract/%s" % contract_id

    subscription_contract_query = """
    query {
      subscriptionContract(id: "%s") {
        id
        createdAt
        status
        nextBillingDate
        customer {
          id
          firstName
          lastName
        }
        billingPolicy { interval intervalCount }
        deliveryPolicy { interval intervalCount }
        customerPaymentMethod {
          id
          instrument {
            __typename
            ... on CustomerCreditCard {
              name
              brand
              lastDigits
              maskedNumber
              expiryMonth
              expiryYear
              isRevocable
              expiresSoon
              billingAddress {
                address1
                city
                province
                country
                zip
              }
            }
            ... on CustomerPaypalBillingAgreement {
              paypalAccountEmail
              billingAddress {
                address1
                city
                country
                zip
              }
            }
            ... on CustomerShopPayAgreement {
              name
              lastDigits
              maskedNumber
              expiryMonth
              expiryYear
              billingAddress {
                address1
                city
                country
                zip
              }
            }
          }
        }
      }
    }
    """ % contract_gid

    try:
        resp = query_shopify_graphql(shop, access_token, subscription_contract_query)
        if "errors" in resp:
            return jsonify({"error": "Error fetching subscription contract", "details": resp["errors"]}), 400

        data = resp["data"]["subscriptionContract"]
        if not data:
            return jsonify({"error": "No subscription contract data returned", "details": resp}), 400

        instr = data["customerPaymentMethod"]["instrument"]
        tname = instr["__typename"]

        cardholder_name = instr.get("name")
        brand = None

        if tname == "CustomerCreditCard":
            brand = instr.get("brand")
        elif tname == "CustomerPaypalBillingAgreement":
            brand = "paypal"
        elif tname == "CustomerShopPayAgreement":
            brand = "shop_pay"

        if tname == "CustomerShopPayAgreement":
            last4 = instr.get("lastDigits")
            customer_gid = data["customer"]["id"]

            customer_cards_query = """
            query {
              customer(id: "%s") {
                paymentMethods(first: 50) {
                  edges {
                    node {
                      ... on CustomerCreditCard {
                        brand
                        lastDigits
                      }
                    }
                  }
                }
              }
            }
            """ % customer_gid

            cards_resp = query_shopify_graphql(shop, access_token, customer_cards_query)
            if "errors" not in cards_resp:
                for edge in cards_resp["data"]["customer"]["paymentMethods"]["edges"]:
                    card = edge["node"]
                    if card.get("lastDigits") == last4:
                        brand = card.get("brand")
                        break

        data["paymentMethodBrand"] = brand
        data["cardholderName"] = cardholder_name

        return jsonify({
            "message": "Subscription contract information retrieved successfully.",
            "data": data
        })

    except Exception as e:
        app.logger.error(f"Error fetching subscription contract info: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500





@app.route("/createWebhook", methods=["POST"])
def create_webhook():
    # Ensure shop parameter is available
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Webhook subscription mutation
    webhook_create_mutation = """
    mutation webhookSubscriptionCreate($topic: WebhookSubscriptionTopic!, $webhookSubscription: WebhookSubscriptionInput!) {
      webhookSubscriptionCreate(topic: $topic, webhookSubscription: $webhookSubscription) {
        webhookSubscription {
          id
          topic
          format
          endpoint {
            __typename
            ... on WebhookHttpEndpoint {
              callbackUrl
            }
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    # Webhook data (hard-coded for dev store)
    topic = "DISPUTES_CREATE"
    callback_url = (
        "https://"
        "sb-92635328-5453-4b15-b3fb-8622b6cbd00d!b82992|it-rt-rezi-glb-ci-qa!b56186:"
        "faa0d131-adf2-4eaa-8377-930dc2ae543a$PKr-cD3RCvLvbT7FZqMl13EyNIA8UhZOh55zZ_wt8zg="
        "@rezi-glb-ci-qa.it-cpi019-rt.cfapps.us10-002.hana.ondemand.com"
        "/http/DisputesCreate"
    )
    format = "JSON"

    # Variables to pass to Shopify
    variables = {
        "topic": topic,
        "webhookSubscription": {
            "callbackUrl": callback_url,
            "format": format
        }
    }

    try:
        # Register the webhook
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, webhook_create_mutation, variables)

        # Check for GraphQL errors
        if "errors" in response:
            return jsonify({
                "error": "Error creating webhook",
                "details": response["errors"]
            }), 400

        # Extract the created webhook
        webhook_subscription = (
            response.get("data", {})
                    .get("webhookSubscriptionCreate", {})
                    .get("webhookSubscription")
        )
        if not webhook_subscription:
            return jsonify({
                "error": "No webhook subscription data returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Webhook created successfully.",
            "data": webhook_subscription
        })

    except Exception as e:
        app.logger.error(f"Error creating webhook: {e}")
        return jsonify({
            "error": "An unexpected error occurred",
            "details": str(e)
        }), 500

@app.route("/createSellingPlanGroup", methods=["POST"])
def create_selling_plan_group():
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    create_selling_plan_group_mutation = """
    mutation createSellingPlanGroup($input: SellingPlanGroupInput!, $resources: SellingPlanGroupResourceInput) {
      sellingPlanGroupCreate(input: $input, resources: $resources) {
        sellingPlanGroup {
          id
          sellingPlans(first: 1) {
            edges {
              node {
                id
              }
            }
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    selling_plan_input = {
        "name": "Subscribe and Save (First Month Free)",
        "merchantCode": "subscribe-first-month-free",
        "options": ["Delivery every"],
        "position": 1,
        "sellingPlansToCreate": [
            {
                "name": "Delivered every month",
                "options": "1 Month",
                "position": 1,
                "category": "SUBSCRIPTION",
                "billingPolicy": {
                    "recurring": {
                        "anchors": {
                            "type": "MONTHDAY",
                            "day": 15
                        },
                        "interval": "MONTH",
                        "intervalCount": 1
                    }
                },
                "deliveryPolicy": {
                    "recurring": {
                        "anchors": {
                            "type": "MONTHDAY",
                            "day": 15
                        },
                        "cutoff": 0,
                        "intent": "FULFILLMENT_BEGIN",
                        "interval": "MONTH",
                        "intervalCount": 1,
                        "preAnchorBehavior": "ASAP"
                    }
                },
                "pricingPolicies": [
                    {
                        "fixed": {
                            "adjustmentType": "PERCENTAGE",
                            "adjustmentValue": {
                                "percentage": 100  # First order is free
                            }
                        }    
                    }
                ]
            }
        ]
    }

    resources = {
        "productIds": [
            "gid://shopify/Product/7652957749313"
        ],
        "productVariantIds": []
    }

    variables = {
        "input": selling_plan_input,
        "resources": resources
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, create_selling_plan_group_mutation, variables)

        if "errors" in response:
            return jsonify({
                "error": "Error creating selling plan group",
                "details": response["errors"]
            }), 400

        selling_plan_group = response.get("data", {}).get("sellingPlanGroupCreate", {}).get("sellingPlanGroup")
        if not selling_plan_group:
            return jsonify({
                "error": "No selling plan group data returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Selling Plan Group created successfully.",
            "data": selling_plan_group
        })

    except Exception as e:
        app.logger.error(f"Error creating selling plan group: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500








@app.route("/customer/<customer_id>/subscription-contracts-recent", methods=["GET"])
def get_recent_subscription_contract_recent(customer_id):
    shop = request.args.get("shop")
    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400
    
    query = f"""
    query {{
      subscriptionContracts(first: 10, query: "customer:{customer_id}") {{
        edges {{
          node {{
            id
            createdAt
            status
            nextBillingDate
            customer {{
              firstName
              lastName
            }}
            billingPolicy {{
              interval
              intervalCount
            }}
            deliveryPolicy {{
              interval
              intervalCount
            }}
          }}
        }}
      }}
    }}
    """
    
    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error fetching subscription contracts", "details": response["userErrors"]}), 400
        if "data" not in response or not response["data"]["subscriptionContracts"]["edges"]:
            return jsonify({"error": "No subscription contracts found for this customer"}), 404
        
        contracts = response["data"]["subscriptionContracts"]["edges"]
        
        # Sort the contracts by createdAt field in descending order
        sorted_contracts = sorted(contracts, key=lambda x: x["node"]["createdAt"], reverse=True)
        
        # Get the most recent contract
        most_recent_contract = sorted_contracts[0]["node"]
        
        contract_data = {
            "id": most_recent_contract["id"],
            "createdAt": most_recent_contract["createdAt"],
            "status": most_recent_contract["status"],
            "nextBillingDate": most_recent_contract["nextBillingDate"],
            "customer": most_recent_contract["customer"],
            "billingPolicy": most_recent_contract["billingPolicy"],
            "deliveryPolicy": most_recent_contract["deliveryPolicy"]
        }
        
        return jsonify({"subscription_contract": contract_data})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/getWebhooks", methods=["GET"])
def get_webhooks():
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    url = f"https://{shop}/admin/api/2023-10/webhooks.json"  # Use the latest API version
    headers = {
        "X-Shopify-Access-Token": ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return jsonify({
                "error": "Failed to fetch webhooks",
                "details": response.json()
            }), response.status_code

        webhooks = response.json().get("webhooks", [])
        if not webhooks:
            return jsonify({
                "error": "No webhooks found for the store.",
                "details": response.json()
            }), 400

        return jsonify({
            "message": "Webhooks fetched successfully.",
            "data": webhooks
        })

    except Exception as e:
        app.logger.error(f"Error fetching webhooks: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500



@app.route("/add-line-to-subscription-draft-atr", methods=["POST"])
def add_line_to_subscription_draft_atr():
    shop = request.args.get("shop")

    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    draft_id = request.json.get("draft_id")
    line_items = request.json.get("line_items", [])
    order_note = request.json.get("order_note")

    if not draft_id or not line_items:
        return jsonify({"error": "Missing required parameters"}), 400

    mutation_results = []

    for item in line_items:
        product_variant_id = item.get("product_variant_id")
        quantity = item.get("quantity")
        price = item.get("price")
        line_item_attributes = item.get("line_item_attributes", [])

        if not product_variant_id or quantity is None or price is None:
            mutation_results.append({
                "error": "Missing fields in line item",
                "item": item
            })
            continue

        # Format line item attributes
        attributes_gql = ""
        if line_item_attributes:
            formatted_attrs = []
            for attr in line_item_attributes:
                key = attr.get("key")
                value = attr.get("value")
                if key and value:
                    key = key.replace('"', '\\"')
                    value = value.replace('"', '\\"')
                    formatted_attrs.append('{ key: "%s", value: "%s" }' % (key, value))
            if formatted_attrs:
                attributes_gql = "customAttributes: [%s],\n" % ", ".join(formatted_attrs)

        # GraphQL mutation
        mutation = """
        mutation {
          subscriptionDraftLineAdd(
            draftId: \"%s\"
            input: {
              productVariantId: \"%s\"
              quantity: %d
              currentPrice: %f
              %s
            }
          ) {
            lineAdded {
              id
              title
              variantId
            }
            draft {
              id
            }
            userErrors {
              field
              message
              code
            }
          }
        }
        """ % (draft_id, product_variant_id, quantity, price, attributes_gql)

        try:
            response = query_shopify_graphql(shop, ACCESS_TOKEN, mutation)
            data = response.get("data", {}).get("subscriptionDraftLineAdd", {})

            if data.get("userErrors"):
                mutation_results.append({
                    "error": "Error adding line",
                    "variant_id": product_variant_id,
                    "details": data["userErrors"]
                })
                continue

            mutation_results.append({
                "message": "Line added successfully",
                "variant_id": product_variant_id,
                "line_added": data.get("lineAdded")
            })

        except Exception as e:
            mutation_results.append({
                "error": "Exception while adding line",
                "variant_id": product_variant_id,
                "details": str(e)
            })

    # Add order note if present
    note_result = None
    if order_note:
        safe_note = order_note.replace('"', '\\"').replace("\n", "\\n")
        note_mutation = """
        mutation {
          subscriptionDraftUpdate(
            id: \"%s\"
            input: {
              note: \"%s\"
            }
          ) {
            draft {
              id
              note
            }
            userErrors {
              field
              message
              code
            }
          }
        }
        """ % (draft_id, safe_note)

        try:
            note_response = query_shopify_graphql(shop, ACCESS_TOKEN, note_mutation)
            note_data = note_response.get("data", {}).get("subscriptionDraftUpdate", {})

            if note_data.get("userErrors"):
                note_result = {
                    "error": "Failed to update order note",
                    "details": note_data["userErrors"]
                }
            else:
                note_result = {
                    "message": "Order note added successfully",
                    "note": note_data.get("draft", {}).get("note")
                }

        except Exception as e:
            note_result = {
                "error": "Exception while updating order note",
                "details": str(e)
            }

    return jsonify({
        "results": mutation_results,
        "order_note_result": note_result,
        "message": "Finished processing subscription draft updates."
    })





@app.route("/deleteWebhook", methods=["POST"])
def delete_webhook():
    shop = request.args.get("shop")
    webhook_id = request.args.get("webhook_id")

    if not shop or not webhook_id:
        return jsonify({"error": "Missing 'shop' or 'webhook_id' parameter"}), 400

    webhook_delete_mutation = """
    mutation webhookSubscriptionDelete($id: ID!) {
      webhookSubscriptionDelete(id: $id) {
        deletedWebhookSubscriptionId
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "id": f"gid://shopify/WebhookSubscription/{webhook_id}"
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, webhook_delete_mutation, variables)

        if "errors" in response:
            return jsonify({
                "error": "Error deleting webhook",
                "details": response["errors"]
            }), 400

        deletion_data = response.get("data", {}).get("webhookSubscriptionDelete", {})
        deleted_id = deletion_data.get("deletedWebhookSubscriptionId")
        user_errors = deletion_data.get("userErrors", [])

        if deleted_id:
            return jsonify({
                "message": "Webhook deleted successfully.",
                "deleted_id": deleted_id
            })
        else:
            return jsonify({
                "error": "Webhook could not be deleted.",
                "details": user_errors
            }), 400

    except Exception as e:
        app.logger.error(f"Error deleting webhook: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route("/getSubscriptionByOrder/<order_number>", methods=["GET"])
def get_subscription_by_order(order_number):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    if not order_number:
        return jsonify({"error": "Order number is required"}), 400

    # Get the access token from Authorization header
    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    # Step 1: Get the order details (to fetch customer ID)
    order_gid = "gid://shopify/Order/%s" % order_number
    order_query = """
    query {
      order(id: "%s") {
        id
        customer {
          id
        }
        createdAt
      }
    }
    """ % order_gid

    order_response = query_shopify_graphql(shop, access_token, order_query)

    if "errors" in order_response:
        return jsonify({"error": "Error fetching order data", "details": order_response["errors"]}), 400

    order_data = order_response.get("data", {}).get("order")
    if not order_data or not order_data.get("customer"):
        return jsonify({"error": "Order or customer not found"}), 404

    customer_id = order_data["customer"]["id"]

    # Step 2: Fetch all contracts for this customer
    contract_query = """
    query {
      subscriptionContracts(first: 200, query: "customer:%s") {
        edges {
          node {
            id
            createdAt
            customer {
              id
            }
          }
        }
      }
    }
    """ % customer_id

    contract_response = query_shopify_graphql(shop, access_token, contract_query)

    if "errors" in contract_response:
        return jsonify({"error": "Error fetching subscription contract data", "details": contract_response["errors"]}), 400

    contracts = contract_response.get("data", {}).get("subscriptionContracts", {}).get("edges", [])
    if not contracts:
        return jsonify({"error": "No subscription contracts found for the customer"}), 404

    # Step 3: Sort by createdAt descending and pick the most recent one
    contracts_sorted = sorted(
        contracts,
        key=lambda edge: date_parser.parse(edge["node"]["createdAt"]),
        reverse=True
    )
    most_recent_contract = contracts_sorted[0]["node"]

    return jsonify({
        "order_id": order_number,
        "customer_id": customer_id,
        "subscription_contract": {
            "id": most_recent_contract["id"],
            "createdAt": most_recent_contract["createdAt"]
        }
    })



@app.route("/get-payment-method-update-url/<customer_payment_method_id>", methods=["POST"])
def get_payment_method_update_url(customer_payment_method_id):
    shop = request.args.get("shop")

    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    # Construct the GraphQL mutation to get the update payment method URL
    mutation = """
    mutation customerPaymentMethodGetUpdateUrl($customerPaymentMethodId: ID!) {
      customerPaymentMethodGetUpdateUrl(customerPaymentMethodId: $customerPaymentMethodId) {
        updatePaymentMethodUrl
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "customerPaymentMethodId": f"gid://shopify/CustomerPaymentMethod/{customer_payment_method_id}"
    }

    try:
        # Call the query_shopify_graphql function
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, mutation, variables)

        # Check for user errors in the response
        if "userErrors" in response and response["userErrors"]:
            return jsonify({"error": "Error getting payment method update URL", "details": response["userErrors"]}), 400

        # Extract the update payment method URL from the response
        if "data" not in response or not response["data"]["customerPaymentMethodGetUpdateUrl"]:
            return jsonify({"error": "No update URL found for the customer payment method", "details": response}), 400

        update_url = response["data"]["customerPaymentMethodGetUpdateUrl"]["updatePaymentMethodUrl"]

        return jsonify({
            "message": "Payment method update URL fetched successfully.",
            "update_url": update_url
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/create-draft-from-contract/<subscription_contract_id>", methods=["POST"])
def create_draft_from_contract(subscription_contract_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    # Step 1: Create draft from subscription contract
    create_draft_mutation = """
    mutation subscriptionContractUpdate($contractId: ID!) {
      subscriptionContractUpdate(contractId: $contractId) {
        draft {
          id
          lines(first: 50) {
            edges {
              node {
                id
              }
            }
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "contractId": f"gid://shopify/SubscriptionContract/{subscription_contract_id}"
    }

    try:
        response = query_shopify_graphql_webhook(shop, access_token, create_draft_mutation, variables)

        # Check for the expected structure in the response
        if "data" not in response or "subscriptionContractUpdate" not in response["data"]:
            return jsonify({
                "error": "Unexpected response from Shopify",
                "raw_response": response
            }), 400

        # Access the result of the mutation
        update_result = response["data"]["subscriptionContractUpdate"]
        user_errors = update_result.get("userErrors", [])

        # If there are user errors, return them
        if user_errors:
            return jsonify({
                "error": "Error creating draft from contract",
                "details": user_errors
            }), 400

        # Get the draft data
        draft_data = update_result.get("draft")
        if not draft_data:
            return jsonify({"error": "No draft found in Shopify response", "details": response}), 400

        draft_id = draft_data["id"]
        existing_lines = draft_data.get("lines", {}).get("edges", [])

        # Step 2: Remove all existing lines from the draft (if any)
        if existing_lines:
            for edge in existing_lines:
                line_id = edge["node"]["id"]

                remove_line_mutation = """
                mutation subscriptionDraftLineRemove($draftId: ID!, $lineId: ID!) {
                  subscriptionDraftLineRemove(draftId: $draftId, lineId: $lineId) {
                    draft {
                      id
                    }
                    userErrors {
                      field
                      message
                    }
                  }
                }
                """

                variables = {
                    "draftId": draft_id,
                    "lineId": line_id
                }

                remove_response = query_shopify_graphql_webhook(shop, access_token, remove_line_mutation, variables)

                # Ensure the response contains the expected structure
                if "data" not in remove_response or "subscriptionDraftLineRemove" not in remove_response["data"]:
                    return jsonify({
                        "error": "Unexpected response when removing line",
                        "line_id": line_id,
                        "raw_response": remove_response
                    }), 400

                remove_result = remove_response["data"]["subscriptionDraftLineRemove"]
                if remove_result.get("userErrors"):
                    return jsonify({
                        "error": "Error removing line from draft",
                        "line_id": line_id,
                        "details": remove_result["userErrors"]
                    }), 400

        # Step 3: Return the cleaned draft ID
        return jsonify({
            "message": "Draft created and cleaned successfully.",
            "draft_id": draft_id
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500






@app.route("/createWebhookFromBody", methods=["POST"])
def create_webhook_from_body():
    # Get `shop` from query params (same as before)
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Get `callback_url` and `topic` from JSON body
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    callback_url = data.get("callback_url")
    topic = data.get("topic")

    # Validate body params
    if not callback_url:
        return jsonify({"error": "Missing callback_url in request body"}), 400
    if not topic:
        return jsonify({"error": "Missing topic in request body"}), 400

    # Shopify GraphQL mutation (same)
    webhook_create_mutation = """
    mutation webhookSubscriptionCreate($topic: WebhookSubscriptionTopic!, $webhookSubscription: WebhookSubscriptionInput!) {
      webhookSubscriptionCreate(topic: $topic, webhookSubscription: $webhookSubscription) {
        webhookSubscription {
          id
          topic
          format
          endpoint {
            __typename
            ... on WebhookHttpEndpoint {
              callbackUrl
            }
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    # Construct GraphQL variables
    variables = {
        "topic": topic,
        "webhookSubscription": {
            "callbackUrl": callback_url,
            "format": "JSON"
        }
    }

    try:
        # Send request to Shopify
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, webhook_create_mutation, variables)

        # Handle response
        if "errors" in response:
            return jsonify({
                "error": "Error creating webhook",
                "details": response["errors"]
            }), 400

        webhook_subscription = response.get("data", {}).get("webhookSubscriptionCreate", {}).get("webhookSubscription")
        if not webhook_subscription:
            return jsonify({
                "error": "No webhook subscription data returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Webhook created successfully.",
            "data": webhook_subscription
        })

    except Exception as e:
        app.logger.error(f"Error creating webhook: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route("/getUpdatePaymentUrlFromBody", methods=["POST"])
def get_update_payment_url_from_body():
    # Get `shop` from query params (required)
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Get `customerPaymentMethodId` from JSON body
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    customer_payment_method_id = data.get("customerPaymentMethodId")
    if not customer_payment_method_id:
        return jsonify({"error": "Missing customerPaymentMethodId in request body"}), 400

    # GraphQL mutation
    mutation = """
    mutation customerPaymentMethodGetUpdateUrl($customerPaymentMethodId: ID!) {
      customerPaymentMethodGetUpdateUrl(customerPaymentMethodId: $customerPaymentMethodId) {
        updatePaymentMethodUrl
        userErrors {
          field
          message
        }
      }
    }
    """

    # GraphQL variables
    variables = {
        "customerPaymentMethodId": customer_payment_method_id
    }

    try:
        # Call the shared Shopify GraphQL helper (assumes it's implemented in your app)
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, mutation, variables)

        # Handle top-level GraphQL errors
        if "errors" in response:
            return jsonify({
                "error": "GraphQL request error",
                "details": response["errors"]
            }), 400

        update_url_data = response.get("data", {}).get("customerPaymentMethodGetUpdateUrl")
        if not update_url_data:
            return jsonify({
                "error": "No updatePaymentMethodUrl returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Payment method update URL retrieved successfully.",
            "data": update_url_data
        })

    except Exception as e:
        app.logger.error(f"Error retrieving payment update URL: {e}")
        return jsonify({
            "error": "An unexpected error occurred",
            "details": str(e)
        }), 500

@app.route("/sendCustomerPaymentUpdateEmail", methods=["POST"])
def send_customer_payment_update_email():
    # Get the shop from query parameters
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing 'shop' parameter"}), 400

    # Get request data (payment method ID and email details)
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    customer_payment_method_id = data.get("customerPaymentMethodId")
    email_data = data.get("email")

    if not customer_payment_method_id or not email_data:
        return jsonify({"error": "Missing 'customerPaymentMethodId' or 'email' in request body"}), 400

    # Validate that email fields are present
    required_email_fields = ['from', 'to', 'subject']
    for field in required_email_fields:
        if not email_data.get(field):
            return jsonify({"error": f"Missing '{field}' in email data"}), 400

    # Prepare the mutation query
    mutation = """
    mutation sendCustomerPaymentUpdateEmail(
        $customerPaymentMethodId: ID!, 
        $email: EmailInput!
    ) {
      customerPaymentMethodSendUpdateEmail(
        customerPaymentMethodId: $customerPaymentMethodId, 
        email: $email
      ) {
        customer {
          id
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    # Prepare the variables
    variables = {
        "customerPaymentMethodId": customer_payment_method_id,
        "email": {
            "from": email_data.get("from"),
            "to": email_data.get("to"),
            "subject": email_data.get("subject"),
            "body": email_data.get("body", ""),
            "customMessage": email_data.get("customMessage", ""),
            "bcc": email_data.get("bcc", [])
        }
    }

    try:
        # Call the Shopify GraphQL API to send the email
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, mutation, variables)

        # Check for errors in the response
        if "errors" in response:
            return jsonify({
                "error": "Error sending email",
                "details": response["errors"]
            }), 400

        # Check for successful email sending
        email_response = response.get("data", {}).get("customerPaymentMethodSendUpdateEmail", {})
        if not email_response:
            return jsonify({
                "error": "Email could not be sent",
                "details": response
            }), 400

        return jsonify({
            "message": "Payment method update email sent successfully.",
            "data": email_response
        })

    except Exception as e:
        app.logger.error(f"Error sending payment update email: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route("/updateCustomerEmail", methods=["POST"])
def update_customer_email():
    # Step 1: Get the shop and access token from the query parameters
    shop = request.args.get("shop")

    # Step 2: Get the customer ID and new email from the request body
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    customer_id = data.get("customerId")
    new_email = data.get("newEmail")

    if not customer_id or not new_email:
        return jsonify({"error": "Missing 'customerId' or 'newEmail' in request body"}), 400

    # Step 3: Prepare the GraphQL mutation query to update the customer's email
    mutation = """
    mutation updateCustomerEmail($input: CustomerInput!) {
      customerUpdate(input: $input) {
        customer {
          id
          email
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "input": {
            "id": customer_id,
            "email": new_email
        }
    }

    # Step 4: Make the request to Shopify GraphQL API
    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, mutation, variables)

        # Step 5: Handle the response from Shopify
        if "errors" in response:
            return jsonify({
                "error": "Error updating customer email",
                "details": response["errors"]
            }), 400

        user_errors = response.get("data", {}).get("customerUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({
                "error": "User errors occurred",
                "details": user_errors
            }), 400

        # Step 6: Access the updated customer data
        updated_customer = response.get("data", {}).get("customerUpdate", {}).get("customer", {})
        if not updated_customer:
            return jsonify({
                "error": "Failed to update customer email",
                "details": response
            }), 400

        # Step 7: Return the success response
        return jsonify({
            "message": "Customer email updated successfully",
            "data": updated_customer
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/update-draft-billing-date", methods=["POST"])
def update_draft_billing_date():
    shop = request.args.get("shop")

    if not shop or not ACCESS_TOKEN:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    data = request.get_json()

    if not data or "draftId" not in data or "input" not in data:
        return jsonify({"error": "Invalid request body. Must contain 'draftId' and 'input'."}), 400

    draft_id = data["draftId"]
    input_data = data["input"]

    # GraphQL mutation to update the next billing date
    update_draft_mutation = """
    mutation subscriptionDraftUpdate($draftId: ID!, $input: SubscriptionDraftInput!) {
      subscriptionDraftUpdate(draftId: $draftId, input: $input) {
        draft {
          id
          nextBillingDate
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "draftId": draft_id,
        "input": input_data
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, update_draft_mutation, variables)

        if "data" not in response or "subscriptionDraftUpdate" not in response["data"]:
            return jsonify({
                "error": "Unexpected response from Shopify",
                "raw_response": response
            }), 400

        update_result = response["data"]["subscriptionDraftUpdate"]
        user_errors = update_result.get("userErrors", [])

        if user_errors:
            return jsonify({
                "error": "Failed to update draft",
                "details": user_errors
            }), 400

        updated_draft = update_result.get("draft")

        return jsonify({
            "message": "Draft updated successfully",
            "draft": updated_draft
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/order/transactions-status", methods=["GET"])
def get_order_transactions_status():
    shop = request.args.get("shop")
    order_id = request.args.get("order_id")

    if not shop or not order_id:
        return jsonify({"error": "Missing required parameters: shop or order_id"}), 400

    # Format the order ID to Shopify's Global ID format
    formatted_order_id = f"gid://shopify/Order/{order_id}"

    query = """
    query getOrderTransactions($orderId: ID!) {
      order(id: $orderId) {
        id
        name
        transactions(first: 10) {
          id
          status
        }
      }
    }
    """

    variables = {
        "orderId": formatted_order_id
    }

    try:
        # Call the query_shopify_graphql function to make the GraphQL request
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, query, variables)

        # Check for any errors in the response
        if "errors" in response:
            return jsonify({"error": "GraphQL error", "details": response["errors"]}), 400

        # Extract the order and transactions from the response
        order = response.get("data", {}).get("order")
        if not order:
            return jsonify({"error": "Order not found"}), 404

        transactions = []
        for transaction in order.get("transactions", []):
            transactions.append({
                "id": transaction.get("id"),
                "status": transaction.get("status")
            })

        # Return the order and transaction details
        return jsonify({
            "order_id": order.get("id"),
            "order_name": order.get("name"),
            "transactions": transactions
        })
    
    except Exception as e:
        # Catch any exceptions and log the error for debugging purposes
        logging.error(f"Error fetching order transactions: {str(e)}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route("/<contract_id>/charge-billing-cycle", methods=["POST"])
def charge_billing_cycle(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    data = request.get_json()
    billing_date = data.get("billing_date")
    if not billing_date:
        return jsonify({"error": "Missing billing_date in request body"}), 400

    formatted_contract_id = f"gid://shopify/SubscriptionContract/{contract_id}"

    # 🚨 Mutation must be anonymous (no "mutation subscriptionBillingCycleCharge")
    subscription_billing_cycle_charge_mutation = """
        mutation ($contractId: ID!, $billingCycleSelector: SubscriptionBillingCycleSelector!) {
          subscriptionBillingCycleCharge(
            subscriptionContractId: $contractId,
            billingCycleSelector: $billingCycleSelector
          ) {
            subscriptionBillingAttempt {
              id
              ready
              errorMessage
              order {
                id
              }
            }
            userErrors {
              field
              message
            }
          }
        }
    """

    variables = {
        "contractId": formatted_contract_id,
        "billingCycleSelector": {
            "date": billing_date
        }
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, subscription_billing_cycle_charge_mutation, variables)

        user_errors = response.get("data", {}).get("subscriptionBillingCycleCharge", {}).get("userErrors", [])
        billing_attempt = response.get("data", {}).get("subscriptionBillingCycleCharge", {}).get("subscriptionBillingAttempt")

        if user_errors:
            return jsonify({
                "error": "Error charging billing cycle",
                "details": user_errors
            }), 400

        if not billing_attempt:
            return jsonify({
                "error": "No billing attempt returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Billing cycle charged successfully.",
            "billing_attempt_id": billing_attempt.get("id"),
            "ready": billing_attempt.get("ready"),
            "error_message": billing_attempt.get("errorMessage"),
            "order_id": billing_attempt.get("order", {}).get("id")
        })

    except Exception as e:
        app.logger.error(f"Error charging billing cycle: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route("/<contract_id>/update-customer-email-and-send-payment-email", methods=["POST"])
def update_email_and_send_payment_email(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Step 1: Get request body
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    new_email = data.get("newEmail")
    if not new_email:
        return jsonify({"error": "Missing 'newEmail' in request body"}), 400

    # Format contract ID
    formatted_contract_id = f"gid://shopify/SubscriptionContract/{contract_id}"

    # Step 2: Get subscription contract info (customer + payment method)
    subscription_contract_query = """
    query {
      subscriptionContract(id: "%s") {
        customer {
          id
        }
        customerPaymentMethod {
          id
        }
      }
    }
    """ % formatted_contract_id

    try:
        sub_response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_contract_query)

        if "errors" in sub_response:
            return jsonify({"error": "Error fetching subscription contract", "details": sub_response["errors"]}), 400

        contract_data = sub_response.get("data", {}).get("subscriptionContract")
        if not contract_data:
            return jsonify({"error": "Subscription contract not found", "details": sub_response}), 404

        customer_id = contract_data["customer"]["id"]
        payment_method_id = contract_data.get("customerPaymentMethod", {}).get("id")

        if not customer_id or not payment_method_id:
            return jsonify({"error": "Missing customer or payment method in subscription contract"}), 400

        # Step 3: Update customer email
        update_email_mutation = """
        mutation updateCustomerEmail($input: CustomerInput!) {
          customerUpdate(input: $input) {
            customer {
              id
              email
            }
            userErrors {
              field
              message
            }
          }
        }
        """
        email_variables = {
            "input": {
                "id": customer_id,
                "email": new_email
            }
        }

        update_response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, update_email_mutation, email_variables)

        if "errors" in update_response:
            return jsonify({"error": "Error updating customer email", "details": update_response["errors"]}), 400

        update_errors = update_response.get("data", {}).get("customerUpdate", {}).get("userErrors", [])
        if update_errors:
            return jsonify({"error": "User error updating email", "details": update_errors}), 400

        # Step 4: Send payment method update email
        send_email_mutation = """
        mutation sendCustomerPaymentUpdateEmail($customerPaymentMethodId: ID!, $email: EmailInput!) {
          customerPaymentMethodSendUpdateEmail(
            customerPaymentMethodId: $customerPaymentMethodId,
            email: $email
          ) {
            customer {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
        """
        email_payload = {
            "customerPaymentMethodId": payment_method_id,
            "email": {
                "from": data.get("from"),
                "to": new_email,
                "subject": data.get("subject", "Update your payment method"),
                "body": data.get("body", ""),
                "customMessage": data.get("customMessage", ""),
                "bcc": data.get("bcc", [])
            }
        }

        send_response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, send_email_mutation, email_payload)

        if "errors" in send_response:
            return jsonify({"error": "Error sending email", "details": send_response["errors"]}), 400

        send_errors = send_response.get("data", {}).get("customerPaymentMethodSendUpdateEmail", {}).get("userErrors", [])
        if send_errors:
            return jsonify({"error": "User error sending email", "details": send_errors}), 400

        return jsonify({
            "message": "Customer email updated and payment update email sent successfully",
            "data": {
                "customer_id": customer_id,
                "new_email": new_email,
                "payment_method_id": payment_method_id
            }
        })

    except Exception as e:
        app.logger.error(f"Error in combined email update + email send: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route("/<contract_id>/pause-subscription", methods=["POST"])
def pause_subscription_contract(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Get access token from Authorization header
    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    # Format contract ID
    formatted_contract_id = "gid://shopify/SubscriptionContract/%s" % contract_id

    # GraphQL mutation to pause subscription
    pause_mutation = """
        mutation subscriptionContractPause($subscriptionContractId: ID!) {
          subscriptionContractPause(subscriptionContractId: $subscriptionContractId) {
            contract {
              id
              status
              updatedAt
            }
            userErrors {
              field
              message
            }
          }
        }
    """

    variables = {
        "subscriptionContractId": formatted_contract_id
    }

    try:
        response = query_shopify_graphql_webhook(shop, access_token, pause_mutation, variables=variables)

        mutation_result = response.get("data", {}).get("subscriptionContractPause", {})

        if "userErrors" in mutation_result and mutation_result["userErrors"]:
            return jsonify({
                "error": "Error pausing subscription contract",
                "details": mutation_result["userErrors"]
            }), 400

        contract_info = mutation_result.get("contract")
        if not contract_info:
            return jsonify({
                "error": "No contract returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Subscription contract paused successfully.",
            "contract": contract_info
        })

    except Exception as e:
        app.logger.error("Error pausing subscription contract: %s" % str(e))
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
        
@app.route("/<contract_id>/activate-subscription", methods=["POST"])
def activate_subscription_contract(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Get access token from Authorization header
    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    # Format the contract_id to match Shopify's Global ID format
    formatted_contract_id = "gid://shopify/SubscriptionContract/%s" % contract_id

    # GraphQL mutation to activate subscription
    activate_mutation = """
        mutation subscriptionContractActivate($subscriptionContractId: ID!) {
          subscriptionContractActivate(subscriptionContractId: $subscriptionContractId) {
            contract {
              id
              status
              updatedAt
            }
            userErrors {
              field
              message
            }
          }
        }
    """

    variables = {
        "subscriptionContractId": formatted_contract_id
    }

    try:
        response = query_shopify_graphql_webhook(shop, access_token, activate_mutation, variables=variables)

        mutation_result = response.get("data", {}).get("subscriptionContractActivate", {})

        if "userErrors" in mutation_result and mutation_result["userErrors"]:
            return jsonify({
                "error": "Error activating subscription contract",
                "details": mutation_result["userErrors"]
            }), 400

        contract_info = mutation_result.get("contract")
        if not contract_info:
            return jsonify({
                "error": "No contract returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Subscription contract activated successfully.",
            "contract": contract_info
        })

    except Exception as e:
        app.logger.error("Error activating subscription contract: %s" % str(e))
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route("/<contract_id>/cancel-subscription", methods=["POST"])
def cancel_subscription(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    formatted_contract_id = f"gid://shopify/SubscriptionContract/{contract_id}"

    mutation = """
    mutation {
      subscriptionContractCancel(id: "%s", reason: CUSTOMER_REQUEST) {
        subscriptionContract {
          id
          status
        }
        userErrors {
          field
          message
        }
      }
    }
    """ % formatted_contract_id

    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, mutation)

        errors = response.get("data", {}).get("subscriptionContractCancel", {}).get("userErrors", [])
        if errors:
            return jsonify({"error": "Could not cancel subscription", "details": errors}), 400

        contract = response["data"]["subscriptionContractCancel"]["subscriptionContract"]

        return jsonify({
            "message": "Subscription cancelled successfully",
            "subscription_contract": contract
        })

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

@app.route("/customer/<customer_id>/contracts-by-payment-method", methods=["GET"])
def get_contracts_by_payment_method(customer_id):
    shop = request.args.get("shop")
    payment_method_plain_id = request.args.get("payment_method_id")

    if not shop or not payment_method_plain_id:
        return jsonify({"error": "Missing shop or payment_method_id parameter"}), 400

    # Get access token from Authorization header
    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    # Convert plain IDs to GID format
    formatted_customer_id = "gid://shopify/Customer/%s" % customer_id
    formatted_payment_method_id = "gid://shopify/CustomerPaymentMethod/%s" % payment_method_plain_id

    query = """
    query {
      subscriptionContracts(first: 50, query: "customer:%s") {
        edges {
          node {
            id
            createdAt
            updatedAt
            status
            nextBillingDate
            customer {
              firstName
              lastName
            }
            billingPolicy {
              interval
              intervalCount
            }
            deliveryPolicy {
              interval
              intervalCount
            }
            customerPaymentMethod {
              id
              instrument {
                __typename
              }
            }
          }
        }
      }
    }
    """ % formatted_customer_id

    try:
        response = query_shopify_graphql(shop, access_token, query)

        if "errors" in response:
            return jsonify({"error": "GraphQL error", "details": response["errors"]}), 400

        contracts = response.get("data", {}).get("subscriptionContracts", {}).get("edges", [])
        if not contracts:
            return jsonify({"message": "No subscription contracts found for this customer"}), 404

        matching_contracts = []
        for edge in contracts:
            contract = edge["node"]
            method = contract.get("customerPaymentMethod")
            if method and method.get("id") == formatted_payment_method_id:
                matching_contracts.append(contract)

        if not matching_contracts:
            return jsonify({"message": "No contracts found with that payment method"}), 404

        return jsonify({"matching_contracts": matching_contracts})

    except Exception as e:
        app.logger.error("Error retrieving contracts by payment method: %s" % str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

@app.route("/<contract_id>/expire-subscription", methods=["POST"])
def expire_subscription_contract(contract_id):
    # Ensure 'shop' parameter is available
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Get the access token from Authorization header
    access_token = request.headers.get("X-Shopify-Access-Token")
    if not access_token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if access_token.lower().startswith("bearer "):
        access_token = access_token.split(" ", 1)[1]

    # Format the contract_id to match Shopify's Global ID format
    formatted_contract_id = "gid://shopify/SubscriptionContract/%s" % contract_id

    # Define the GraphQL mutation for expiring a subscription contract
    expire_mutation = """
    mutation subscriptionContractExpire($subscriptionContractId: ID!) {
      subscriptionContractExpire(subscriptionContractId: $subscriptionContractId) {
        contract {
          id
          status
          updatedAt
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    # Variables for the mutation
    variables = {
        "subscriptionContractId": formatted_contract_id
    }

    try:
        # Send the GraphQL request
        response = query_shopify_graphql_webhook(shop, access_token, expire_mutation, variables=variables)

        # Extract the mutation result
        mutation_result = response.get("data", {}).get("subscriptionContractExpire", {})

        # Handle user errors
        if "userErrors" in mutation_result and mutation_result["userErrors"]:
            return jsonify({
                "error": "Error expiring subscription contract",
                "details": mutation_result["userErrors"]
            }), 400

        # Get contract info from response
        contract_info = mutation_result.get("contract")
        if not contract_info:
            return jsonify({
                "error": "No contract returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Subscription contract expired successfully.",
            "contract": contract_info
        })

    except Exception as e:
        app.logger.error("Error expiring subscription contract: %s" % e)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route("/<customer_id>/update-customer", methods=["POST"])
def update_customer(customer_id):
    # Ensure 'shop' parameter is available
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Ensure 'customerAccessToken' parameter is available
    customer_access_token = request.args.get("customerAccessToken")
    if not customer_access_token:
        return jsonify({"error": "Missing customerAccessToken parameter"}), 400

    # Define the GraphQL mutation for updating the customer
    customer_update_mutation = """
        mutation customerUpdate($customer: CustomerUpdateInput!, $customerAccessToken: String!) {
          customerUpdate(customer: $customer, customerAccessToken: $customerAccessToken) {
            customer {
              id
              firstName
              lastName
              email
              phone
              acceptsMarketing
            }
            customerAccessToken {
              accessToken
            }
            customerUserErrors {
              field
              message
            }
            userErrors {
              field
              message
            }
          }
        }
    """

    # Prepare the variables for the mutation
    variables = {
        "customer": {
            "id": customer_id,  # Shopify Customer ID
            "acceptsMarketing": True,
            "email": "<your-email>",  # Update with the new email
            "firstName": "<your-firstName>",  # Update with the new first name
            "lastName": "<your-lastName>",  # Update with the new last name
            "password": "<your-password>",  # Update with the new password
            "phone": "<your-phone>"  # Update with the new phone number
        },
        "customerAccessToken": customer_access_token  # Customer's access token
    }

    try:
        # Send the GraphQL request
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, customer_update_mutation, variables=variables)

        # Extract the mutation result
        mutation_result = response.get("data", {}).get("customerUpdate", {})

        # Handle user errors
        if "userErrors" in mutation_result and mutation_result["userErrors"]:
            return jsonify({
                "error": "Error updating customer",
                "details": mutation_result["userErrors"]
            }), 400

        # Get customer info from response
        customer_info = mutation_result.get("customer")
        if not customer_info:
            return jsonify({
                "error": "No customer returned",
                "details": response
            }), 400

        return jsonify({
            "message": "Customer updated successfully.",
            "customer": customer_info
        })

    except Exception as e:
        app.logger.error(f"Error updating customer: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500



@app.route("/<contract_id>/charge-subscription-now", methods=["POST"])
def charge_subscription_now(contract_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Format the contract_id to match Shopify's Global ID format
    formatted_contract_id = f"gid://shopify/SubscriptionContract/{contract_id}"

    # Valid GraphQL mutation to create the upcoming order immediately
    create_upcoming_order_mutation = """
    mutation CreateUpcomingOrder($id: ID!) {
      subscriptionContractCreateUpcomingOrder(id: $id) {
        upcomingOrder {
          id
          status
          createdAt
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "id": formatted_contract_id
    }

    try:
        # Send the GraphQL request
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, create_upcoming_order_mutation, variables)

        mutation_result = response.get("data", {}).get("subscriptionContractCreateUpcomingOrder", {})

        # Check for user errors
        if mutation_result.get("userErrors"):
            return jsonify({
                "error": "Failed to create upcoming order.",
                "details": mutation_result["userErrors"]
            }), 400

        upcoming_order = mutation_result.get("upcomingOrder")
        if not upcoming_order:
            return jsonify({
                "error": "No upcoming order returned.",
                "details": response
            }), 400

        return jsonify({
            "message": "Upcoming order created successfully.",
            "upcoming_order": upcoming_order
        })

    except Exception as e:
        app.logger.error(f"Error creating upcoming order: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

import re
from flask import request, jsonify

@app.route("/payment-method/<payment_method_id>/subscription-contracts", methods=["GET"])
def get_subscription_contracts_for_payment_method(payment_method_id):
    shop = request.args.get("shop")

    if not shop:
        return jsonify({"error": "Missing required 'shop' parameter"}), 400

    payment_method_gid = "gid://shopify/CustomerPaymentMethod/%s" % payment_method_id

    graphql_query = """
    query {
      customerPaymentMethod(id: "%s") {
        id
        customer {
          id
          firstName
          lastName
          email
          note
        }
        instrument {
          __typename
          ... on CustomerCreditCard {
            brand
            lastDigits
            expiryMonth
            expiryYear
          }
          ... on CustomerPaypalBillingAgreement {
            paypalAccountEmail
          }
          ... on CustomerShopPayAgreement {
            lastDigits
            expiryMonth
            expiryYear
          }
        }
        subscriptionContracts(first: 50) {
          edges {
            node {
              id
              status
              createdAt
              nextBillingDate
              customer {
                id
                firstName
                lastName
              }
              billingPolicy {
                interval
                intervalCount
              }
              deliveryPolicy {
                interval
                intervalCount
              }
            }
          }
        }
      }
    }
    """ % payment_method_gid

    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, graphql_query)

        if "errors" in response:
            return jsonify({"error": "Error querying Shopify", "details": response["errors"]}), 400

        data = response.get("data", {}).get("customerPaymentMethod")
        if not data:
            return jsonify({"error": "No payment method found with that ID"}), 404

        # Extract email from the customer's note
        note = data.get("customer", {}).get("note", "")
        extracted_email = None
        match = re.search(r"Email:\s*([^\s<]+@[^\s<]+)", note)
        if match:
            extracted_email = match.group(1)

        # Flatten subscription contracts
        edges = data.get("subscriptionContracts", {}).get("edges", [])
        flattened_contracts = [edge["node"] for edge in edges]

        return jsonify({
            "customerPaymentMethod": {
                "id": data["id"],
                "customer": data["customer"],
                "instrument": data["instrument"],
                "subscriptionContracts": flattened_contracts
            },
            "extractedEmailFromNote": extracted_email
        })

    except Exception as e:
        app.logger.error("Error querying subscription contracts by payment method: %s" % str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500



from flask import request, jsonify

@app.route("/<customer_id>/update-customer-info", methods=["POST"])
def update_customer_info(customer_id):
    # 1) shop param
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # 2) JSON payload: email, firstName, lastName
    body = request.get_json() or {}
    email      = body.get("email")
    first_name = body.get("firstName")
    last_name  = body.get("lastName")

    if not all([email, first_name, last_name]):
        return jsonify({
            "error": "Missing required fields",
            "required": ["email", "firstName", "lastName"]
        }), 400

    # 3) Build the Admin API GID for the customer
    customer_gid = f"gid://shopify/Customer/{customer_id}"

    # 4) Admin GraphQL mutation
    mutation = """
    mutation customerUpdate($input: CustomerInput!) {
      customerUpdate(input: $input) {
        customer {
          id
          email
          firstName
          lastName
        }
        userErrors {
          field
          message
        }
      }
    }
    """


    variables = {
        "input": {
            "id":        customer_gid,
            "email":     email,
            "firstName": first_name,
            "lastName":  last_name
        }
    }


    try:
        # 5) Call your helper, which should post to:
        #    https://{shop}/admin/api/2025-01/graphql.json
        response = query_shopify_graphql_webhook(
            shop,
            ACCESS_TOKEN,
            mutation,
            variables=variables
        )

        data       = response.get("data", {}).get("customerUpdate", {})
        user_errors = data.get("userErrors", [])

        if user_errors:
            return jsonify({
                "error": "Failed to update customer",
                "userErrors": user_errors
            }), 400

        updated = data.get("customer")
        if not updated:
            return jsonify({
                "error": "No customer returned",
                "raw": response
            }), 500

        return jsonify({
            "message":  "Customer updated successfully",
            "customer": updated
        }), 200

    except Exception as e:
        app.logger.exception("Error updating customer")
        return jsonify({
            "error":   "Unexpected error",
            "details": str(e)
        }), 500

@app.route("/webhook/order-created", methods=["POST"])
def handle_order_created_webhook():
    # 1) Ensure shop query param
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # 2) Parse the incoming JSON
    payload = request.get_json(silent=True) or {}

    # 3) Pull out all note_attributes into a flat dict
    additional_info = {
        attr.get("name") or attr.get("key"): attr.get("value")
        for attr in payload.get("note_attributes", [])
        if (attr.get("name") or attr.get("key"))
    }

    # 4) If there's nothing to do, short-circuit
    if not additional_info:
        return jsonify({"message": "No additional info found. Skipping."}), 200

    # 5) Get customer ID directly from Shopify payload
    customer_id = payload.get("customer", {}).get("id")
    customer_gid = f"gid://shopify/Customer/{customer_id}" if customer_id else None

    email = additional_info.get("email")
    full_name = additional_info.get("org_unit_name")
    if not all([customer_gid, email, full_name]):
        return jsonify({"message": "Required fields missing. Skipping."}), 200

    # 6) Split full name into first/last
    parts = full_name.strip().split(" ", 1)
    first_name = parts[0]
    last_name = parts[1] if len(parts) > 1 else ""

    # 7) Check if the email is already associated with an existing customer
    customer_query = """
    query($email: String!) {
      customers(first: 1, query: $email) {
        edges {
          node {
            id
            email
          }
        }
      }
    }
    """
    query_vars = {"email": email}
    existing_customer = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, customer_query, query_vars)

    app.logger.error("Customer lookup response:\n" + json.dumps(existing_customer, indent=2))

    existing_edges = (
        existing_customer.get("data", {}).get("customers", {}).get("edges", [])
    )

    if existing_edges:
        # Email exists, merge the current customer with the existing one
        existing_customer_id = existing_edges[0]["node"]["id"]
        merge_mutation = """
        mutation($customerOneId: ID!, $customerTwoId: ID!) {
          customerMerge(customerOneId: $customerOneId, customerTwoId: $customerTwoId) {
            job {
              id
            }
            resultingCustomerId
            userErrors {
              field
              message
            }
          }
        }
        """
        merge_vars = {
            "customerOneId": customer_gid,
            "customerTwoId": existing_customer_id,
        }
        merge_response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, merge_mutation, merge_vars)

        app.logger.error("Customer merge response:\n" + json.dumps(merge_response, indent=2))

        merge_data = merge_response.get("data", {}).get("customerMerge")
        if not merge_data:
            return jsonify({
                "error": "Unexpected response from customerMerge",
                "raw": merge_response
            }), 500

        user_errors = merge_data.get("userErrors", [])
        if user_errors:
            return jsonify({
                "error": "Customer merge failed",
                "details": user_errors
            }), 400

        return jsonify({"message": "Customers merged successfully"}), 200

    else:
        # Email doesn't exist, update the current customer
        update_mutation = """
        mutation customerUpdate($input: CustomerInput!) {
          customerUpdate(input: $input) {
            customer {
              id
              email
              firstName
              lastName
            }
            userErrors {
              field
              message
            }
          }
        }
        """
        update_vars = {
            "input": {
                "id": customer_gid,
                "email": email,
                "firstName": first_name,
                "lastName": last_name
            }
        }
        update_response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, update_mutation, update_vars)

        app.logger.error("Customer update response:\n" + json.dumps(update_response, indent=2))

        update_data = update_response.get("data", {}).get("customerUpdate")
        if not update_data:
            return jsonify({
                "error": "Unexpected response from customerUpdate",
                "raw": update_response
            }), 500

        user_errors = update_data.get("userErrors", [])
        if user_errors:
            return jsonify({
                "error": "Failed to update customer",
                "details": user_errors
            }), 400

        return jsonify({"message": "Customer info updated from order webhook"}), 200


@app.route("/getSubscriptionByCustomer/<customer_id>", methods=["GET"])
def get_subscription_by_customer(customer_id):
    shop = request.args.get("shop")
    if not shop or not customer_id:
        return jsonify({"error": "Missing shop or customer_id parameter"}), 400

    all_contracts = []
    has_next_page = True
    cursor = None

    while has_next_page:
        # Build the GraphQL query with pagination support
        contract_query = (
            "query {"
            "  subscriptionContracts(first: 100, query: \"customer:{0}\", after: \"{1}\") {"
            "    edges {"
            "      node {"
            "        id"
            "        createdAt"
            "        status"
            "        customer {"
            "          id"
            "          email"
            "        }"
            "      }"
            "    }"
            "    pageInfo {"
            "      hasNextPage"
            "      endCursor"
            "    }"
            "  }"
            "}".format(customer_id, cursor if cursor else "")
        )

        # Send the query to Shopify
        contract_response = query_shopify_graphql(shop, ACCESS_TOKEN, contract_query)

        if "errors" in contract_response:
            return jsonify({"error": "Error fetching subscription contract data", "details": contract_response["errors"]}), 400

        contracts = contract_response.get("data", {}).get("subscriptionContracts", {}).get("edges", [])
        if not contracts:
            return jsonify({"error": "No subscription contracts found for the customer"}), 404

        # Append the contracts to the all_contracts list
        all_contracts.extend(contracts)

        # Get the pagination info to check if there's more data
        page_info = contract_response.get("data", {}).get("subscriptionContracts", {}).get("pageInfo", {})
        has_next_page = page_info.get("hasNextPage", False)
        cursor = page_info.get("endCursor", None)

    # Sort contracts by createdAt in descending order (most recent first)
    sorted_contracts = sorted(
        all_contracts,
        key=lambda edge: edge["node"]["createdAt"],
        reverse=True
    )

    # Return the most recent contract (or all if needed)
    most_recent_contract = sorted_contracts[0]["node"]  # Getting the most recent one
    return jsonify({
        "customer_id": customer_id,
        "most_recent_subscription_contract": {
            "id": most_recent_contract["id"],
            "createdAt": most_recent_contract["createdAt"],
            "status": most_recent_contract["status"],
            "customer": most_recent_contract["customer"]
        }
    })

@app.route("/order/<order_id>/latest-subscription-contract", methods=["GET"])
def latest_subscription_contract(order_id):
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    try:
        # 1. Get customer GID from the order ID
        order_gid = f"gid://shopify/Order/{order_id}"
        order_query = """
        query ($id: ID!) {
          order(id: $id) {
            customer {
              id
            }
          }
        }
        """
        order_resp = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, order_query, {"id": order_gid})
        if order_resp.get("errors"):
            return jsonify({"error": "Error fetching order", "details": order_resp["errors"]}), 400

        customer_data = order_resp.get("data", {}).get("order", {}).get("customer")
        if not customer_data:
            return jsonify({"error": "Order found but no associated customer"}), 404

        customer_gid = customer_data["id"]

        # 2. Get customer's subscription contracts directly
        contract_query = """
        query ($id: ID!) {
          customer(id: $id) {
            subscriptionContracts(first: 50) {
              edges {
                node {
                  id
                  updatedAt
                  status
                  customerPaymentMethod {
                    id
                  }
                }
              }
            }
          }
        }
        """
        contract_resp = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, contract_query, {"id": customer_gid})
        if contract_resp.get("errors"):
            return jsonify({"error": "Error fetching contracts", "details": contract_resp["errors"]}), 400

        contracts = contract_resp.get("data", {}).get("customer", {}).get("subscriptionContracts", {}).get("edges", [])
        if not contracts:
            return jsonify({"error": "No subscription contracts found for customer"}), 404

        # 3. Pick latest by updatedAt
        latest = max(
            [edge["node"] for edge in contracts if "node" in edge],
            key=lambda c: date_parser.parse(c["updatedAt"])
        )

        return jsonify({
            "order_id": order_id,
            "customer_id": customer_gid,
            "latest_subscription_contract": latest
        })

    except Exception as e:
        app.logger.exception("Unexpected error")
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500
        


@app.route("/<order_id>/rescheduleFulfillment", methods=["POST"])
def reschedule_fulfillment(order_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    new_fulfill_at = request.json.get("new_fulfill_at")
    if not new_fulfill_at:
        return jsonify({"error": "Missing new fulfillment date"}), 400

    try:
        # 1. Retrieve the Fulfillment Order ID using the Order ID
        order_gid = f"gid://shopify/Order/{order_id}"
        order_query = """
        query($id: ID!) {
          order(id: $id) {
            fulfillmentOrders(first: 1) {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
        """
        order_response = query_shopify_graphql_webhook(shop, access_token, order_query, {"id": order_gid})
        
        if "errors" in order_response:
            return jsonify({"error": "Error fetching fulfillment orders", "details": order_response["errors"]}), 400
        
        fulfillment_order_gid = None
        fulfillment_orders = order_response.get("data", {}).get("order", {}).get("fulfillmentOrders", {}).get("edges", [])
        
        if fulfillment_orders:
            fulfillment_order_gid = fulfillment_orders[0]["node"]["id"]
        
        if not fulfillment_order_gid:
            return jsonify({"error": "No fulfillment orders found for this order"}), 404

        # 2. Construct the GraphQL mutation to reschedule the fulfillment
        mutation = """
        mutation {
          fulfillmentOrderReschedule(
            id: "%s",
            fulfillAt: "%s"
          ) {
            fulfillmentOrder {
              id
              status
              fulfillAt
            }
            userErrors {
              field
              message
            }
          }
        }
        """ % (fulfillment_order_gid, new_fulfill_at)

        # 3. Execute the mutation to reschedule the fulfillment order
        response = query_shopify_graphql(shop, access_token, mutation)
        
        if "errors" in response:
            return jsonify({"error": "Error rescheduling fulfillment", "details": response["errors"]}), 400

        data = response.get("data", {}).get("fulfillmentOrderReschedule")
        if not data or data.get("userErrors"):
            return jsonify({"error": "Shopify error", "details": data.get("userErrors")}), 400

        return jsonify({
            "message": "Fulfillment order rescheduled successfully.",
            "data": data["fulfillmentOrder"]
        })

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route("/getPaymentMethodInfo", methods=["POST"])
def get_payment_method_info():
    data = request.get_json()
    shop = request.args.get("shop")
    payment_method_id = data.get("payment_method_id")

    if not shop or not payment_method_id:
        return jsonify({"error": "Missing required parameters"}), 400

    # Query for payment method info
    base_query = """
    query {
      customerPaymentMethod(id: "PAYMENT_METHOD_ID") {
        id
        customer {
          id
          note
        }
        instrument {
          __typename
          ... on CustomerCreditCard {
            name
            brand
            lastDigits
            maskedNumber
            expiryMonth
            expiryYear
            billingAddress {
              address1
              city
              province
              provinceCode
              country
              countryCode
              zip
            }
          }
          ... on CustomerPaypalBillingAgreement {
            paypalAccountEmail
            billingAddress {
              address1
              city
              province
              provinceCode
              country
              countryCode
              zip
            }
          }
          ... on CustomerShopPayAgreement {
            name
            lastDigits
            maskedNumber
            expiryMonth
            expiryYear
            billingAddress {
              address1
              city
              province
              provinceCode
              country
              countryCode
              zip
            }
          }
        }
      }
    }
    """

    query = base_query.replace("PAYMENT_METHOD_ID", payment_method_id)

    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, query)

        if "errors" in response:
            return jsonify({"error": "GraphQL error", "details": response["errors"]}), 400

        pm_data = response["data"]["customerPaymentMethod"]
        customer = pm_data.get("customer", {})
        note = customer.get("note", "")

        # Extract email from customer note
        email = None
        match = re.search(r"Email:\s*([^\s<]+@[^\s<]+)", note)
        if match:
            email = match.group(1)

        return jsonify({
            "message": "Payment method info retrieved successfully.",
            "data": pm_data,
            "extractedEmailFromNote": email
        })

    except Exception as e:
        app.logger.error(f"Error retrieving payment method info: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
        
@app.route("/subscriptions", methods=["GET"])
def subscriptions_page():
    shop = request.args.get("shop")
    subscription_id = request.args.get("id")

    if not shop or not subscription_id:
        return jsonify({"error": "Missing required parameters"}), 400

    subscription_gid = "gid://shopify/SubscriptionContract/%s" % subscription_id

    subscription_query = """
    query {
      subscriptionContract(id: "%s") {
        id
        status
        createdAt
        updatedAt
        nextBillingDate
        customer {
          id
          firstName
          lastName
          email
        }
        billingPolicy {
          interval
          intervalCount
        }
        deliveryPolicy {
          interval
          intervalCount
        }
        deliveryMethod {
          __typename
          ... on SubscriptionDeliveryMethodShipping {
            address {
              name
              address1
              address2
              city
              province
              zip
              country
            }
          }
        }
        customerPaymentMethod {
          id
        }
        lines(first: 10) {
          edges {
            node {
              id
              title
              variantTitle
              quantity
            }
          }
        }
      }
    }
    """ % subscription_gid

    try:
        # First query: get subscription contract
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_query)

        if "errors" in response:
            return jsonify({"error": "GraphQL query failed", "details": response["errors"]}), 400

        subscription = response.get("data", {}).get("subscriptionContract")
        if not subscription:
            return jsonify({"error": "No subscription contract found with that ID"}), 404

        # Extract payment method ID and customer ID
        customer_pm = subscription.get("customerPaymentMethod")
        payment_method_id = customer_pm["id"] if customer_pm else None
        customer_id = subscription["customer"]["id"] if subscription.get("customer") else None

        # Second query: get payment method instrument details
        instrument_details = None
        payment_brand = None
        cardholder_name = None

        if payment_method_id:
            payment_query = """
            query {
              customerPaymentMethod(id: "%s") {
                id
                instrument {
                  __typename
                  ... on CustomerCreditCard {
                    name
                    brand
                    lastDigits
                    maskedNumber
                    expiryMonth
                    expiryYear
                    isRevocable
                    expiresSoon
                    billingAddress {
                      address1
                      city
                      province
                      country
                      zip
                    }
                  }
                  ... on CustomerPaypalBillingAgreement {
                    paypalAccountEmail
                    billingAddress {
                      address1
                      city
                      country
                      zip
                    }
                  }
                  ... on CustomerShopPayAgreement {
                    name
                    lastDigits
                    maskedNumber
                    expiryMonth
                    expiryYear
                    billingAddress {
                      address1
                      city
                      country
                      zip
                    }
                  }
                }
              }
            }
            """ % payment_method_id

            payment_response = query_shopify_graphql(shop, ACCESS_TOKEN, payment_query)

            if "errors" not in payment_response:
                instrument_details = payment_response["data"]["customerPaymentMethod"]["instrument"]
                tname = instrument_details["__typename"]

                cardholder_name = instrument_details.get("name")
                if tname == "CustomerCreditCard":
                    payment_brand = instrument_details.get("brand")
                elif tname == "CustomerPaypalBillingAgreement":
                    payment_brand = "paypal"
                elif tname == "CustomerShopPayAgreement":
                    payment_brand = "shop_pay"
                    # Try to resolve Shop Pay brand if missing
                    last4 = instrument_details.get("lastDigits")
                    if last4 and customer_id:
                        customer_cards_query = """
                        query {
                          customer(id: "%s") {
                            paymentMethods(first: 50) {
                              edges {
                                node {
                                  ... on CustomerCreditCard {
                                    brand
                                    lastDigits
                                  }
                                }
                              }
                            }
                          }
                        }
                        """ % customer_id

                        cards_resp = query_shopify_graphql(shop, ACCESS_TOKEN, customer_cards_query)
                        if "errors" not in cards_resp:
                            for edge in cards_resp["data"]["customer"]["paymentMethods"]["edges"]:
                                card = edge["node"]
                                if card.get("lastDigits") == last4:
                                    payment_brand = card.get("brand")
                                    break

        # Inject additional info into the subscription dict for the template
        subscription["paymentMethodInstrument"] = instrument_details
        subscription["paymentMethodBrand"] = payment_brand
        subscription["cardholderName"] = cardholder_name

        return render_template("subscriptions.html",
                               subscription=subscription)

    except Exception as e:
        app.logger.error("Error querying subscription contract: %s", str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

@app.route("/subscription-contract/<subscription_contract_id>/update-to-daily", methods=["POST"])
def update_subscription_contract_to_daily(subscription_contract_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("X-Shopify-Access-Token")

    if not shop:
        return jsonify({"error": "Missing required 'shop' parameter"}), 400

    if not access_token:
        return jsonify({"error": "Missing 'X-Shopify-Access-Token' header"}), 401

    # Format the GID for the subscription contract
    contract_gid = "gid://shopify/SubscriptionContract/%s" % subscription_contract_id

    # GraphQL mutation to update billingPolicy
    graphql_mutation = """
    mutation {
      subscriptionContractUpdate(
        id: "%s",
        input: {
          billingPolicy: {
            interval: DAY,
            intervalCount: 1
          }
        }
      ) {
        subscriptionContract {
          id
          billingPolicy {
            interval
            intervalCount
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    """ % contract_gid

    try:
        response = query_shopify_graphql(shop, access_token, graphql_mutation)

        # Log the full GraphQL response
        app.logger.debug("Full GraphQL response: %s", json.dumps(response, indent=2))

        update_data = response.get("data", {}).get("subscriptionContractUpdate", {})
        user_errors = update_data.get("userErrors", [])
        subscription_contract = update_data.get("subscriptionContract")

        if user_errors:
            return jsonify({
                "contract_id": subscription_contract_id,
                "errors": user_errors
            }), 400

        if not subscription_contract:
            return jsonify({
                "contract_id": subscription_contract_id,
                "error": "No subscriptionContract returned"
            }), 400

        return jsonify({
            "updated_contract": subscription_contract
        })

    except Exception as e:
        app.logger.error("Error updating contract to daily: %s" % str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

@app.route("/contracts")
def list_all_contracts():
    shop = request.args.get("shop")
    if not shop:
        return jsonify({"error": "Missing shop parameter"}), 400

    # Pagination and sorting params
    after = request.args.get("after")
    page = int(request.args.get("page", 1))
    sort_by = request.args.get("sort_by", "createdAt desc")
    before_stack_raw = request.args.get("before_stack", "[]")
    reset = request.args.get("reset") == "1"

    # Clean up invalid/empty params
    if after in [None, "", "null", "None"]:
        after = None

    # Reset pagination if requested
    if reset:
        after = None
        before_stack_raw = "[]"
        page = 1

    try:
        before_stack = json.loads(before_stack_raw)
    except json.JSONDecodeError:
        before_stack = []

    # Build GraphQL query args - only pagination and sorting now
    graphql_args = 'first: 10'
    if after:
        graphql_args += f', after: "{after}"'

    graphql_query = f"""
    query {{
      subscriptionContracts({graphql_args}) {{
        edges {{
          cursor
          node {{
            id
            status
            nextBillingDate
            createdAt
            updatedAt
            customer {{
              id
              firstName
              lastName
              email
            }}
            lines(first: 3) {{
              edges {{
                node {{
                  title
                  quantity
                }}
              }}
            }}
          }}
        }}
        pageInfo {{
          hasNextPage
        }}
      }}
    }}
    """

    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, graphql_query)

        if "errors" in response:
            return jsonify({"error": "GraphQL query failed", "details": response["errors"]}), 400

        data = response["data"]["subscriptionContracts"]
        edges = data["edges"]
        contracts = [edge["node"] for edge in edges]
        cursors = [edge["cursor"] for edge in edges]
        last_cursor = cursors[-1] if cursors else None
        has_next_page = data["pageInfo"]["hasNextPage"]

        # Sort client-side
        field, direction = sort_by.split()
        reverse = direction == "desc"
        if field in {"createdAt", "updatedAt", "nextBillingDate", "status"}:
            contracts.sort(key=lambda c: c.get(field) or "", reverse=reverse)

        # Update before_stack for back pagination
        updated_before_stack = before_stack.copy()
        if after:
            updated_before_stack.append(after)

        prev_cursor = None
        prev_stack = before_stack.copy()
        if page > 1 and before_stack:
            prev_cursor = before_stack[-1]
            prev_stack = before_stack[:-1]

        return render_template(
            "contracts.html",
            contracts=contracts,
            shop=shop,
            page=page,
            has_next_page=has_next_page,
            next_cursor=last_cursor,
            prev_cursor=prev_cursor,
            before_stack=json.dumps(updated_before_stack),
            prev_stack=json.dumps(prev_stack),
            sort_by=sort_by,
        )

    except Exception as e:
        app.logger.error("Error fetching subscription contracts: %s", str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@app.route("/selling-plans", methods=["GET", "POST"])
def selling_plans():
    # Get shop from the query parameters for both GET and POST requests
    shop = request.args.get("shop")  # Use request.args to get query parameters (for GET request)
    
    if request.method == "POST":
        # For POST request, we fetch other form fields as usual
        name = request.form.get("name")
        description = request.form.get("description")
        # Get product IDs from the form input, split by commas and strip spaces
        product_ids = [pid.strip() for pid in request.form.get("product_ids").split(",")]

        # Validate product IDs
        if not product_ids or any(not pid.isdigit() for pid in product_ids):
            return jsonify({"error": "Invalid product IDs provided"}), 400

        # Discount percentage
        discount_percentage = request.form.get("discount_percentage")

        # Format product GIDs
        product_gids = ['gid://shopify/Product/{}'.format(pid) for pid in product_ids]

        # Check if we are updating an existing selling plan or creating a new one
        selling_plan_id = request.form.get("selling_plan_id")

        if selling_plan_id:
            # Update existing selling plan
            mutation = """
            mutation {
              sellingPlanGroupUpdate(input: {
                id: "%s",
                name: "%s",
                description: "%s",
                pricingPolicies: [{
                  fixed: {
                    adjustmentType: PERCENTAGE,
                    adjustmentValue: {
                      percentage: %s
                    }
                  }
                }],
                resourceSelection: {
                  selectionType: ENTIRE,
                  resources: %s
                }
              }) {
                sellingPlanGroup {
                  id
                  name
                }
                userErrors {
                  field
                  message
                }
              }
            }
            """ % (
                selling_plan_id,
                name,
                description,
                discount_percentage,
                product_gids
            )
        else:
            # Create new selling plan
            mutation = """
            mutation {
              sellingPlanGroupCreate(input: {
                name: "%s",
                description: "%s",
                merchantCode: "%s",
                options: ["One-time Upsell"],
                sellingPlans: [{
                  name: "%s",
                  position: 1,
                  billingPolicy: {
                    recurring: {
                      interval: MONTH,
                      intervalCount: 1
                    }
                  },
                  deliveryPolicy: {
                    recurring: {
                      interval: MONTH,
                      intervalCount: 1
                    }
                  },
                  pricingPolicies: [
                    {
                      fixed: {
                        adjustmentType: PERCENTAGE,
                        adjustmentValue: {
                          percentage: %s
                        }
                      }
                    }
                  ]
                }],
                resourceSelection: {
                  selectionType: ENTIRE,
                  resources: %s
                }
              }) {
                sellingPlanGroup {
                  id
                  name
                }
                userErrors {
                  field
                  message
                }
              }
            }
            """ % (
                name,
                description,
                name.lower().replace(" ", "_"),
                name,
                discount_percentage,
                product_gids
            )

        try:
            # Query Shopify GraphQL API
            response = query_shopify_graphql(shop, ACCESS_TOKEN, mutation)
            if "errors" in response or response["data"]["sellingPlanGroupCreate"]["userErrors"]:
                return jsonify({"error": "Mutation failed", "details": response}), 400

            # Extract the Selling Plan Group ID
            selling_plan_id = response["data"]["sellingPlanGroupCreate"]["sellingPlanGroup"]["id"]
            return render_template("selling_plan_success.html", selling_plan_id=selling_plan_id)

        except Exception as e:
            app.logger.error("Error creating/updating selling plan group: %s", str(e))
            return jsonify({"error": "Unexpected error", "details": str(e)}), 500

    # If GET request, fetch existing selling plans to populate the dropdown
    try:
        selling_plans_query = """
        query {
          sellingPlanGroups(first: 10) {
            edges {
              node {
                id
                name
              }
            }
          }
        }
        """
        # Ensure that the 'shop' variable is passed correctly here
        selling_plans_response = query_shopify_graphql(shop, SHOPIFY_ADMIN_ACCESS_TOKEN, selling_plans_query)
        selling_plans = selling_plans_response["data"]["sellingPlanGroups"]["edges"] if "data" in selling_plans_response else []

        return render_template("selling_plan_form.html", selling_plans=[plan["node"] for plan in selling_plans], action_text="Create")

    except Exception as e:
        app.logger.error("Error fetching selling plans: %s", str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

import re
from flask import request, jsonify

@app.route("/customer/<customer_id>/email-from-notes", methods=["GET"])
def get_customer_email_from_notes(customer_id):
    shop = request.args.get("shop")
    access_token = request.headers.get("Authorization")

    if not shop or not access_token:
        return jsonify({"error": "Missing shop query parameter or Authorization header"}), 400

    query = f"""
    query {{
      customer(id: "gid://shopify/Customer/{customer_id}") {{
        id
        note
      }}
    }}
    """

    try:
        response = query_shopify_graphql(shop, access_token, query)

        if "errors" in response:
            return jsonify({"error": "GraphQL error", "details": response["errors"]}), 400

        customer_data = response.get("data", {}).get("customer")
        if not customer_data or not customer_data.get("note"):
            return jsonify({"error": "Customer not found or note is empty"}), 404

        note = customer_data["note"]

        # Use regex to extract the email from the note
        match = re.search(r"Email:\s*([^\s<]+@[^\s<]+)", note)
        if not match:
            return jsonify({"error": "Email not found in customer note"}), 404

        email = match.group(1)

        return jsonify({
            "id": customer_data["id"],
            "email": email
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/<subscription_id>/subscription-info", methods=["GET"])
def get_subscription_info(subscription_id):
    shop = request.args.get("shop")

    if not shop or not subscription_id:
        return jsonify({"error": "Missing required parameters"}), 400

    subscription_gid = "gid://shopify/SubscriptionContract/%s" % subscription_id

    subscription_query = """
    query {
      subscriptionContract(id: "%s") {
        id
        status
        createdAt
        updatedAt
        nextBillingDate
        customer {
          id
          firstName
          lastName
          email
        }
        billingPolicy {
          interval
          intervalCount
        }
        deliveryPolicy {
          interval
          intervalCount
        }
        deliveryMethod {
          __typename
          ... on SubscriptionDeliveryMethodShipping {
            address {
              name
              address1
              address2
              city
              province
              zip
              country
            }
          }
        }
        customerPaymentMethod {
          id
        }
        lines(first: 10) {
          edges {
            node {
              id
              title
              variantTitle
              quantity
            }
          }
        }
      }
    }
    """ % subscription_gid

    try:
        response = query_shopify_graphql(shop, ACCESS_TOKEN, subscription_query)

        if "errors" in response:
            return jsonify({"error": "GraphQL query failed", "details": response["errors"]}), 400

        subscription = response.get("data", {}).get("subscriptionContract")
        if not subscription:
            return jsonify({"error": "No subscription contract found with that ID"}), 404

        return jsonify(subscription)

    except Exception as e:
        app.logger.error("Error fetching subscription info: %s", str(e))
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

@app.route("/updateSellingPlanGroupResources", methods=["POST"])
def update_selling_plan_group_resources():
    shop = request.args.get("shop")
    selling_plan_group_id_short = request.args.get("sellingPlanGroupId")
    variant_id = request.args.get("variantId")
    product_id = request.args.get("productId")

    # Validate query params
    if not shop or not selling_plan_group_id_short or not variant_id or not product_id:
        return jsonify({
            "error": "Missing one or more required parameters",
            "required": ["shop", "sellingPlanGroupId", "variantId", "productId"]
        }), 400

    # Convert numeric IDs to GIDs
    selling_plan_group_gid = f"gid://shopify/SellingPlanGroup/{selling_plan_group_id_short}"
    product_gid = f"gid://shopify/Product/{product_id}"
    variant_gid = f"gid://shopify/ProductVariant/{variant_id}"

    # Correct GraphQL mutation structure
    update_mutation = """
    mutation updateSellingPlanGroup($input: SellingPlanGroupUpdateInput!) {
      sellingPlanGroupUpdate(input: $input) {
        sellingPlanGroup {
          id
          name
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    # Properly formatted input object
    variables = {
        "input": {
            "id": selling_plan_group_gid,
            "resources": {
                "productIds": [product_gid],
                "productVariantIds": [variant_gid]
            }
        }
    }

    try:
        # Your existing function to execute a GraphQL query
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, update_mutation, variables)

        # Handle top-level GraphQL errors
        if "errors" in response:
            return jsonify({
                "error": "GraphQL execution error",
                "details": response["errors"]
            }), 400

        # Handle userErrors from the mutation
        user_errors = response.get("data", {}).get("sellingPlanGroupUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({
                "error": "Shopify returned user errors",
                "details": user_errors
            }), 400

        # Return success
        updated_group = response.get("data", {}).get("sellingPlanGroupUpdate", {}).get("sellingPlanGroup")

        return jsonify({
            "message": "✅ Selling Plan Group successfully updated.",
            "data": updated_group
        })

    except Exception as e:
        app.logger.error(f"Error updating selling plan group: {e}")
        return jsonify({"error": "Unexpected server error", "details": str(e)}), 500

@app.route("/sellingPlanGroupInfo", methods=["POST"])
def selling_plan_group_info():
    data = request.get_json()
    shop = data.get("shop")
    selling_plan_group_id = data.get("sellingPlanGroupId")  # Changed here
    
    if not shop or not selling_plan_group_id:
        return jsonify({"error": "Missing 'shop' or 'sellingPlanGroupId' in request body"}), 400

    query = """
    query getSellingPlanGroup($id: ID!) {
      sellingPlanGroup(id: $id) {
        id
        name
        appSaleChannels {
          id
          name
        }
        sellingPlans(first: 10) {
          edges {
            node {
              id
              name
            }
          }
        }
      }
    }
    """

    variables = {
        "id": selling_plan_group_id
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, query, variables)
        
        if "errors" in response:
            return jsonify({"error": "GraphQL error", "details": response["errors"]}), 400
        
        group = response.get("data", {}).get("sellingPlanGroup")
        if not group:
            return jsonify({"error": "Selling plan group not found"}), 404

        return jsonify({
            "sellingPlanGroupId": group["id"],
            "sellingPlanGroupName": group["name"],
            "salesChannels": group.get("appSaleChannels", []),
            "sellingPlans": [edge["node"] for edge in group.get("sellingPlans", {}).get("edges", [])]
        })

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500






        
@app.route("/get-customer-payment-methods", methods=["POST"])
def get_customer_payment_methods():
    shop = request.args.get("shop")
    data = request.get_json()

    customer_id = data.get("customerId")

    if not shop or not ACCESS_TOKEN or not customer_id:
        return jsonify({"error": "Missing shop, access token, or customerId"}), 400

    query = """
    query getCustomerPaymentMethods($id: ID!) {
      customer(id: $id) {
        paymentMethods(first: 10) {
          edges {
            node {
              id
            }
          }
        }
      }
    }
    """

    variables = {
        "id": customer_id
    }

    try:
        response = query_shopify_graphql_webhook(shop, ACCESS_TOKEN, query, variables)

        if "data" not in response or "customer" not in response["data"]:
            return jsonify({"error": "Unexpected response", "details": response}), 400

        edges = response["data"]["customer"].get("paymentMethods", {}).get("edges", [])
        payment_method_ids = [edge["node"]["id"] for edge in edges]

        return jsonify({
            "paymentMethodIds": payment_method_ids
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

import logging
app.logger.setLevel(logging.DEBUG)

@app.route("/webhook/order-created-update-db", methods=["POST"])
def handle_order_created_update_db():
    try:
        # Always log raw data

        # Try to parse JSON
        try:
            payload = request.get_json(force=True)  # force parse, throw error if bad
        except Exception as e:
            app.logger.error(f"❌ JSON parse error: {e}")
            payload = {}

        # Extract note attributes
        note_attributes = {
            (attr.get("name") or attr.get("key")): attr.get("value")
            for attr in payload.get("note_attributes", [])
            if (attr.get("name") or attr.get("key"))
        }
        app.logger.warning(f"📝 Note Attributes: {note_attributes}")

        cart_id = note_attributes.get("cart_id")
        if not cart_id:
            app.logger.warning("⚠️ No cart-id found, returning early.")
            return jsonify({"message": "No cart-id found. Skipping."}), 200

        # Build request body for external DB
        request_body = {
            "cart_id": cart_id,
            "hasItem": False,
            "products": ""
        }
        app.logger.info(f"➡️ Sending update to DB: {request_body}")

        url = "https://cart-status.azurewebsites.net/api/pro/cart/update-hasItem"
        response = requests.post(url, json=request_body, timeout=10)

        try:
            data = response.json()
        except Exception:
            data = {"raw": response.text}

        if data.get("isSuccess"):
            app.logger.info(f"✅ Cart {cart_id} marked as closed in DB")
            return jsonify({"message": f"Cart {cart_id} updated successfully"}), 200
        else:
            app.logger.error(f"❌ Failed DB update for cart {cart_id}: {data}")
            return jsonify({"error": "Failed to update cart in DB", "details": data}), 500

    except Exception as e:
        app.logger.error(f"🔥 Exception in webhook: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/schedule-next-billing/<subscription_contract_id>", methods=["POST"])
def schedule_next_billing(subscription_contract_id):
    shop = request.args.get("shop")
    access_token = ACCESS_TOKEN

    if not shop or not access_token:
        return jsonify({"error": "Missing shop parameter or access token"}), 400

    # --- Step 1: Set target billing date to the very end of today ---
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    target_date = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    target_date_iso = target_date.isoformat().replace("+00:00", "Z")

    # --- Step 2: GraphQL mutation ---
    mutation = """
    mutation subscriptionContractSetNextBillingDate($contractId: ID!, $date: DateTime!) {
      subscriptionContractSetNextBillingDate(
        contractId: $contractId,
        date: $date
      ) {
        contract {
          id
          nextBillingDate
        }
        userErrors {
          field
          message
        }
      }
    }
    """

    variables = {
        "contractId": f"gid://shopify/SubscriptionContract/{subscription_contract_id}",
        "date": target_date_iso
    }

    try:
        response = query_shopify_graphql_webhook(shop, access_token, mutation, variables)
        result = response.get("data", {}).get("subscriptionContractSetNextBillingDate", {})

        if result.get("userErrors"):
            return jsonify({
                "error": "Error updating next billing date",
                "details": result["userErrors"]
            }), 400

        updated_contract = result.get("contract")
        if not updated_contract:
            return jsonify({"error": "No contract returned", "response": response}), 400

        return jsonify({
            "message": "Next billing date updated to the end of today successfully.",
            "subscription_contract": updated_contract
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
