import os
import requests, json, time
from flask import Flask, request, jsonify, render_template_string, render_template, redirect, session
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
import hmac
import hashlib
import base64
import jwt
from flask_sqlalchemy import SQLAlchemy
import time
from threading import Thread
import re
from math import ceil



SCHEMA_CACHE = {
    "timestamp": 0,
    "organization_fields": []
}

# Cache lifetime – 24 hours (in seconds)
CACHE_TTL = 60 * 60 * 24

# Load environment variables
load_dotenv()

app = Flask(__name__)


BATCH_SIZE = 10  # Number of products/collections per batch
SLEEP_BETWEEN_REQUESTS = 0.2  # Delay between Shopify requests to avoid rate limits
# Store Locally?
allowed_origins = [
    "https://www.xxx",
    "https://xxx",
    "https://nontransferrnick.myshopify.com"
]

CORS(app, origins=allowed_origins, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Shopify API credentials
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
#Likely just need read/write products, metafields, and metaobjects
SCOPES = os.getenv(
    "SHOPIFY_SCOPES",
    "read_customers,write_orders,read_orders,read_own_subscription_contracts,write_own_subscription_contracts,manage_orders_information,read_orders,write_orders,read_discounts,write_discounts,read_shopify_payments_disputes",
)
ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN") # Can be retrieved dynamically on calls, where do we store for each client or do we fetch each time with our auth callback flow? More calls but more secure


# Hardcoded Admin API credentials (ONLY FOR SERVER-SIDE USAGE)
SHOPIFY_ADMIN_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN")
SHOPIFY_API_VERSION = "2024-01"  # or current stable version

# Initialize Flask app

class StoreToken(db.Model):
    __tablename__ = "store_tokens"
    id = db.Column(db.Integer, primary_key=True)
    shop = db.Column(db.String(255), unique=True, nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())


def fetch_organization_schema_properties():
    """
    Fetches and parses Schema.org vocabulary to extract
    Organization properties.
    Uses in-memory caching for speed.
    """

    now = time.time()

    # ---------------------------------
    # 1. Return cached if still fresh
    # ---------------------------------
    if now - SCHEMA_CACHE["timestamp"] < CACHE_TTL:
        return SCHEMA_CACHE["organization_fields"]

    # ---------------------------------
    # 2. Fetch file from Schema.org
    # ---------------------------------
    url = "https://schema.org/version/latest/schemaorg-current-https.jsonld"
    resp = requests.get(url)
    data = resp.json()

    graph = data["@graph"]

    # Filter only properties
    properties = [p for p in graph if p.get("@type") == "rdf:Property"]

    org_fields = []
    for prop in properties:
        domain = prop.get("schema:domainIncludes")
        if not domain:
            continue

        # Normalize
        domain_list = domain if isinstance(domain, list) else [domain]

        # Check if Organization is included
        if any(d.get("@id") == "schema:Organization" for d in domain_list):
            org_fields.append(prop["@id"].split(":")[-1])

    org_fields.sort()

    # ---------------------------------
    # 3. Update cache
    # ---------------------------------
    SCHEMA_CACHE["timestamp"] = now
    SCHEMA_CACHE["organization_fields"] = org_fields

    return org_fields

def graphql_request(shop, token, query, variables=None):
    url = f"https://{shop}/admin/api/2025-10/graphql.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": token
    }
    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    resp = requests.post(url, headers=headers, json=payload)
    resp.raise_for_status()
    return resp.json()
# ----------------------------
# Flask API Route
# ----------------------------

@app.route("/api/schema/org-fields")
def api_get_org_schema_fields():
    """
    Returns a lightweight JSON list:
    ["address", "email", "logo", ...]
    """
    fields = fetch_organization_schema_properties()
    return jsonify({"organization_fields": fields})

def verify_hmac(hmac_value, raw_body):
    calculated = hmac.new(
        SHOPIFY_API_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(calculated, hmac_value)


def verify_id_token(id_token):
    return jwt.decode(
        id_token,
        SHOPIFY_API_SECRET,
        algorithms=["HS256"],
        audience=SHOPIFY_API_KEY,
        options={"verify_exp": True}
    )


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

#three parameter graphql helper
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

#four parameter graphql helper
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


#app status check? Remove?
@app.route("/")
def home():
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
    
#access token gen
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
    
    # Save token to DB
    store = StoreToken.query.filter_by(shop=shop).first()
    if store:
        store.access_token = access_token
    else:
        store = StoreToken(shop=shop, access_token=access_token)
        db.session.add(store)
    
    db.session.commit()


    return jsonify(
        {
            "message": "Authorization successful",
            "shop": shop,
            "access_token": access_token,
        }
    )
#list of needed webhooks: products/update, products/create, products/delete, collections/create, collections/delete, collections/update no page/blog webhooks, maybe a sync button in the app interface?
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

#template route for populating app GUI
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

#helper function for app GUI
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
# ---------------- DASHBOARD ----------------
# store the latest dynamic values from Shopify
latest_values = {
    "hmac": None,
    "id_token": None
}


def get_metafield_definitions(shop, access_token):
    query = """
    {
      productDefinitions: metafieldDefinitions(ownerType: PRODUCT, first: 200) {
        edges {
          node {
            id
            name
            namespace
            key
            type {
              name
            }
            description
          }
        }
      }
      collectionDefinitions: metafieldDefinitions(ownerType: COLLECTION, first: 200) {
        edges {
          node {
            id
            name
            namespace
            key
            type {
              name
            }
            description
          }
        }
      }
    }
    """

    return query_shopify_graphql(shop, access_token, query)

@app.route("/app")
def schema_dashboard():
    shop = session.get("shop") or request.args.get("shop")
    hmac = session.get("hmac") or request.args.get("hmac")
    id_token = session.get("id_token") or request.args.get("id_token")

    latest_values["hmac"] = hmac
    latest_values["id_token"] = id_token

    # Fetch access token from DB
    store = StoreToken.query.filter_by(shop=shop).first()
    access_token = store.access_token if store else None

    product_metafields = []
    collection_metafields = []

    if access_token:
        try:
            meta_data = get_metafield_definitions(shop, access_token)
            product_metafields = meta_data["data"]["productDefinitions"]["edges"]
            collection_metafields = meta_data["data"]["collectionDefinitions"]["edges"]
        except Exception as e:
            print("Error fetching metafield definitions:", str(e))

    # ✅ Fetch cached organization fields
    org_fields = fetch_organization_schema_properties()  # will use cache if valid

    schemas = [
        {"title": "Organization Schema", "url": "/app/organization-schema-builder"},
        {"title": "Product Schema", "url": "/app/products-schema-builder"},
        {"title": "Collection Schema", "url": "/app/collections-schema-builder"},
        {"title": "Blog Schema", "url": "/app/blog-schema-builder"},
    ]

    return render_template(
        "schema_dashboard.html",
        schemas=schemas,
        title="Schema App Dashboard",
        shop_name=shop,
        hmac_value=hmac,
        id_token_value=id_token,
        product_metafields=product_metafields,      
        collection_metafields=collection_metafields,
        org_schema_fields=org_fields   # <-- pass cached org schema to template
    )


# ---------------- ORGANIZATION SCHEMA ----------------
@app.route("/app/organization-schema-builder")
def organization_schema():
    shop = request.args.get("shop")
    if not shop:
        return "<p>Error: missing shop parameter</p>"

    query = """
    {
      shop {
        name
        metafields(namespace: "organization", first: 10) {
          edges {
            node {
              id
              key
              value
              type
              description
            }
          }
        }
      }
    }
    """
    try:
        data = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        metafields = data["data"]["shop"]["metafields"]["edges"]
        return render_template("schema_list.html", schema_name="Organization", metafields=metafields, shop=shop)
    except Exception as e:
        return f"<p>Error fetching metafields: {str(e)}</p>"

# ---------------- PRODUCT SCHEMA ----------------
@app.route("/app/products-schema-builder")
def product_schema():
    shop = request.args.get("shop")
    if not shop:
        return "<p>Error: missing shop parameter</p>"

    query = """
    {
      products(first: 10) {
        edges {
          node {
            id
            title
            metafields(namespace: "product", first: 10) {
              edges {
                node {
                  id
                  key
                  value
                  type
                  description
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        data = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        products = data["data"]["products"]["edges"]
        return render_template("product_schema.html", products=products, shop=shop)
    except Exception as e:
        return f"<p>Error fetching products: {str(e)}</p>"

# ---------------- COLLECTION SCHEMA ----------------
@app.route("/app/collections-schema-builder")
def collection_schema():
    shop = request.args.get("shop")
    if not shop:
        return "<p>Error: missing shop parameter</p>"

    query = """
    {
      collections(first: 10) {
        edges {
          node {
            id
            title
            metafields(namespace: "collection", first: 10) {
              edges {
                node {
                  id
                  key
                  value
                  type
                  description
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        data = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        collections = data["data"]["collections"]["edges"]
        return render_template("collection_schema.html", collections=collections, shop=shop)
    except Exception as e:
        return f"<p>Error fetching collections: {str(e)}</p>"

# ---------------- BLOG SCHEMA ----------------
@app.route("/app/blog-schema-builder")
def blog_schema():
    shop = request.args.get("shop")
    if not shop:
        return "<p>Error: missing shop parameter</p>"

    query = """
    {
      articles(first: 10) {
        edges {
          node {
            id
            title
            metafields(namespace: "blog", first: 10) {
              edges {
                node {
                  id
                  key
                  value
                  type
                  description
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        data = query_shopify_graphql(shop, ACCESS_TOKEN, query)
        articles = data["data"]["articles"]["edges"]
        return render_template("blog_schema.html", articles=articles, shop=shop)
    except Exception as e:
        return f"<p>Error fetching blog articles: {str(e)}</p>"

# ---------------- SUPPORT & PRICING ----------------
@app.route("/app/support")
def support():
    return "<h1>Support Page</h1>"

@app.route("/app/pricing")
def pricing():
    return "<h1>Pricing Page</h1>"

@app.route("/create_app_owned_metafields")
def create_app_owned_metafields():
    shop = session.get("shop")
    token = session.get("access_token")  # App access token

    if not shop or not token:
        flash("Shop or access token not found.", "error")
        return redirect(url_for("schema_dashboard"))

    # Define schemas
    schemas = [
        {"namespace": "app_schema", "key": "prod_schema", "ownerType": "PRODUCT"},
        {"namespace": "app_schema", "key": "coll_schema", "ownerType": "COLLECTION"},
        {"namespace": "app_schema", "key": "blog_schema", "ownerType": "BLOG"},
        {"namespace": "app_schema", "key": "page_schema", "ownerType": "PAGE"},
    ]

    # For each schema
    for schema in schemas:
        # 1️⃣ Create definition
        query_def = """
        mutation metafieldDefinitionCreate($definition: MetafieldDefinitionInput!) {
          metafieldDefinitionCreate(definition: $definition) {
            createdDefinition { id namespace key }
            userErrors { field message }
          }
        }
        """
        variables_def = {
            "definition": {
                "name": schema["key"],
                "key": schema["key"],
                "description": f"App schema for {schema['ownerType'].lower()}",
                "type": "json",
                "ownerType": schema["ownerType"],
                "namespace": schema["namespace"]
            }
        }
        resp_def = graphql_request(shop, token, query_def, variables_def)
        errors_def = resp_def.get("data", {}).get("metafieldDefinitionCreate", {}).get("userErrors", [])
        if errors_def:
            print(f"Error creating definition {schema['key']}: {errors_def}")

        # 2️⃣ Upsert default `{}` for all objects
        object_queries = {
            "PRODUCT": "{ products(first:100) { edges { node { id } } } }",
            "COLLECTION": "{ collections(first:100) { edges { node { id } } } }",
            "BLOG": "{ blogs(first:100) { edges { node { id } } } }",
            "PAGE": "{ pages(first:100) { edges { node { id } } } }",
        }
        resp_objects = graphql_request(shop, token, object_queries[schema["ownerType"]], {})
        edges = list(resp_objects.get("data", {}).values())[0].get("edges", [])

        for node in edges:
            numeric_id = node["node"]["id"].split('/')[-1]  # Convert GID to numeric ID if needed
            gid = f"gid://shopify/{schema['ownerType'].capitalize()}/{numeric_id}"


            

            query_upsert = """
            mutation metafieldUpsert($input: MetafieldInput!) {
              metafieldUpsert(input: $input) {
                metafield { id namespace key value type }
                userErrors { field message }
              }
            }
            """
            variables_upsert = {
                "input": {
                    "namespace": schema["namespace"],
                    "key": schema["key"],
                    "ownerId": gid,
                    "type": "json",
                    "value": "{}"
                }
            }
            resp_upsert = graphql_request(shop, token, query_upsert, variables_upsert)
            print(json.dumps(resp_upsert, indent=2))
            errors_upsert = resp_upsert.get("data", {}).get("metafieldUpsert", {}).get("userErrors", [])
            if errors_upsert:
                print(f"Error upserting {schema['key']} for {gid}: {errors_upsert}")

    flash("App-owned schema metafields created and default values upserted!", "success")
    return redirect(url_for("schema_dashboard"))

@app.route("/init-db", methods=["GET"])
def init_db():
    """Create all database tables."""
    try:
        with app.app_context():
            db.create_all()
        return jsonify({"message": "Database initialized successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import threading
import json
import logging
import requests
from flask import Flask, request, jsonify, session

BATCH_SIZE = 20  # Number of products to upsert at once

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("metafields.log"), logging.StreamHandler()]
)

# --- Helper functions ---

def generate_default_organization_schema():
    """
    Fetch organization properties from Schema.org and return
    a dict mapping property name -> default type ("string").
    """
    fields = fetch_organization_schema_properties()  # your existing function
    schema_dict = {field: "string" for field in fields}  # default type
    return schema_dict

def fetch_existing_app_schema(shop, access_token, product_gid):
    """Returns existing app_schema.product_schema as a dict, or {}."""
    url = f"https://{shop}/admin/api/2026-01/graphql.json"
    headers = {"Content-Type": "application/json", "X-Shopify-Access-Token": access_token}

    query = """
    query($id: ID!) {
      product(id: $id) {
        metafield(namespace: "app_schema", key: "product_schema") {
          value
        }
      }
    }
    """
    resp = requests.post(url, json={"query": query, "variables": {"id": product_gid}}, headers=headers)
    resp.raise_for_status()
    node = resp.json()["data"]["product"]["metafield"]
    if not node:
        return {}
    try:
        return json.loads(node["value"])
    except:
        return {}


def get_access_token_for_shop(shop):
    store = StoreToken.query.filter_by(shop=shop).first()
    return store.access_token if store else None

def fetch_product_metafields(shop, access_token, product_id):
    """Fetch all existing metafields for a product."""
    url = f"https://{shop}/admin/api/2026-01/products/{product_id}/metafields.json"
    headers = {"Content-Type": "application/json", "X-Shopify-Access-Token": access_token}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json().get("metafields", [])
    # Return as {key: value}
    return {mf["key"]: mf["value"] for mf in data}

import json
import requests  # Assuming requests is imported in your environment
import logging # Already in use

# --- Helper Function for RMW Read Stage (Necessary for finding the metafield ID) ---
def _find_metafield_by_key_rest(shop, access_token, resource_type, resource_id, namespace, key):
    """
    Retrieves a specific metafield's ID and value using the REST API based on 
    namespace and key. Necessary for implementing Read-Modify-Write (RMW).
    Returns the metafield dictionary (containing 'id', 'value', etc.) or None.
    """
    # Use the plural resource type endpoint to list metafields
    url = f"https://{shop}/admin/api/2026-01/{resource_type}s/{resource_id}/metafields.json"
    headers = {
        "X-Shopify-Access-Token": access_token
    }
    
    # We must list all metafields for the resource and filter client-side
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    
    metafields = resp.json().get('metafields',)
    
    for mf in metafields:
        if mf.get('namespace') == namespace and mf.get('key') == key:
            return mf
            
    return None


def upsert_app_metafield(shop, access_token, owner_gid, value_dict):
    """
    Create or update a JSON app-owned metafield on a resource (e.g., product)
    using the Shopify REST Admin API with Read-Modify-Write (RMW) pattern.
    """
    METAFIELD_NAMESPACE = "app_schema"
    METAFIELD_KEY = "prod_schema"
    
    # 1. Extract Resource Type and ID from the GID (FIXED LOGIC)
    try:
        # Example GID: 'gid://shopify/Product/8149887778991'
        parts = owner_gid.split('/')
        
        # Validate the basic structure (must have 5 parts and start with 'gid:')
        if len(parts) < 5 or parts!= 'gid:': # <-- GID parsing correction applied here
             raise ValueError("Malformed GID structure. GID must start with 'gid:'.")
        
        resource_type = parts[-2].lower()
        resource_id = parts[-1]
    except Exception:
        # Catch any exception during parsing and raise a clean error
        raise ValueError("Invalid owner_gid format. Expected format like 'gid://shopify/Product/123456789'.")

    # --- RMW Step 1: Read Existing State ---
    existing_metafield = _find_metafield_by_key_rest(
        shop, access_token, resource_type, resource_id, METAFIELD_NAMESPACE, METAFIELD_KEY
    )

    if existing_metafield:
        metafield_id = existing_metafield.get('id')
        current_data = {}
        
        # RMW Step 2: Deserialization
        try:
            # Check if the existing value is an empty string before parsing
            existing_value_str = existing_metafield.get('value')
            if existing_value_str:
                current_data = json.loads(existing_value_str)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse existing metafield JSON for {owner_gid} (ID: {metafield_id}): {e}. Starting with empty object.")
            # If parsing fails, start with an empty object to prevent corruption

        # RMW Step 3: Object Mutation (Merge new value_dict into existing data)
        # This prevents the partial value_dict from overwriting all existing keys.
        merged_data = current_data.copy()
        merged_data.update(value_dict)
        
        # RMW Step 4: Re-serialization
        final_json_string = json.dumps(merged_data)
        
        # Determine URL and Method for Write operation (PUT for Update)
        url = f"https://{shop}/admin/api/2026-01/{resource_type}s/{resource_id}/metafields/{metafield_id}.json"
        http_method = requests.put
        log_action = "Updated"
    else:
        # If metafield doesn't exist, we skip RMW and create a new one (POST)
        final_json_string = json.dumps(value_dict)
        
        # Determine URL and Method for Write operation (POST for Create)
        url = f"https://{shop}/admin/api/2026-01/{resource_type}s/{resource_id}/metafields.json"
        http_method = requests.post
        log_action = "Created"

    # 5. Prepare the REST Payload for the Write operation
    payload = {
        "metafield": {
            "type": "json",
            "namespace": METAFIELD_NAMESPACE,
            "key": METAFIELD_KEY, 
            "value": final_json_string  # The full, merged JSON string
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    logging.info(f"Sending {http_method.__name__.upper()} to: {url}")
    logging.debug(f"Payload (Metafield Value String): {final_json_string}")

    # RMW Step 5: Make the Request (PUT/POST)
    resp = http_method(url, headers=headers, json=payload)
    
    # Check for REST API error status (4xx or 5xx)
    resp.raise_for_status()
    
    response_json = resp.json()
    logging.info(f"{log_action} {METAFIELD_NAMESPACE}.{METAFIELD_KEY} for {owner_gid}.")

    return response_json



def fetch_all_products(shop, access_token):
    """Fetch all products with their metafields (paginated)."""
    url = f"https://{shop}/admin/api/2026-01/graphql.json"
    headers = {"Content-Type": "application/json", "X-Shopify-Access-Token": access_token}

    products = []
    cursor = None
    while True:
        query = """
        query ($cursor: String) {
            products(first: 100, after: $cursor) {
                pageInfo { hasNextPage }
                edges {
                    cursor
                    node {
                        id
                    }
                }
            }
        }
        """
        variables = {"cursor": cursor}
        resp = requests.post(url, json={"query": query, "variables": variables}, headers=headers)
        resp.raise_for_status()
        data = resp.json()["data"]["products"]
        for edge in data["edges"]:
            products.append(edge["node"])
        if not data["pageInfo"]["hasNextPage"]:
            break
        cursor = data["edges"][-1]["cursor"]
    return products

# --- Main endpoint ---
@app.route("/verify_and_create_metafields", methods=["POST"])
def verify_and_create_metafields():
    data = request.json
    shop = data.get("shop") or session.get("shop")
    schema_definition = data.get("schema")

    if not schema_definition:
        logging.info("No schema provided, generating default Organization schema")
        schema_definition = generate_default_organization_schema()

    access_token = get_access_token_for_shop(shop)
    if not access_token:
        logging.warning(f"No access token found for shop: {shop}")
        return jsonify({"error": "No access token for shop"}), 400

    def process_metafields():
        try:
            products = fetch_all_products(shop, access_token)
            logging.info(f"Fetched {len(products)} products for shop {shop}")

            for i in range(0, len(products), BATCH_SIZE):
                batch = products[i:i+BATCH_SIZE]
                for product in batch:
                    product_gid = product["id"]  # e.g., gid://shopify/Product/1234567890
                    try:
                        product_id = product_gid.split("/")[-1]

                        # Fetch existing metafields (optional; helps preserve existing values)
                        existing_mfs = fetch_product_metafields(shop, access_token, product_id)
                        logging.info(f"Existing app schema for {product_gid}: {existing_mfs}")

                        # Build full schema JSON
                        schema_value = {}
                        for field_key, field_type in schema_definition.items():
                            val = existing_mfs.get(field_key)
                            if val is None:
                                if field_type == "string":
                                    val = ""
                                elif field_type == "number":
                                    val = 0
                                elif field_type == "boolean":
                                    val = False
                                else:
                                    val = None
                            schema_value[field_key] = val

                        # Upsert metafield using REST API
                        resp = upsert_app_metafield(shop, access_token, product_gid, schema_value)
                        logging.info(f"Upserted app_schema.product_schema for {product_gid}: {schema_value}")
                        logging.debug(f"REST response: {resp}")

                    except Exception as e:
                        logging.error(f"Failed processing product {product_gid}: {e}", exc_info=True)

            logging.info(f"Background processing completed for shop {shop}")

        except Exception as e:
            logging.error(f"Background process failed for shop {shop}: {e}", exc_info=True)

    # Run in background thread
    threading.Thread(target=process_metafields, daemon=True).start()
    logging.info(f"Started background processing for shop {shop}")
    return jsonify({"message": "Started background processing of app-owned metafields. Check logs for progress."})



@app.route("/get_metafields", methods=["POST"])
def get_metafields():
    data = request.json
    shop = data.get("shop")
    hmac = data.get("hmac")
    id_token = data.get("id_token")

    # Fetch access token from DB
    store = StoreToken.query.filter_by(shop=shop).first()
    access_token = store.access_token if store else None

    if not access_token:
        return {"error": "Access token not found for shop"}, 400

    APP_NAMESPACE = "app_schema"

    # Fixed GraphQL query - no string formatting
    query = """
    {
      products(first: 100) {
        edges {
          node {
            id
            title
            metafields(namespace: "app_schema", first: 50) {
              edges {
                node {
                  namespace
                  key
                  value
                  type
                }
              }
            }
          }
        }
      }

      collections(first: 100) {
        edges {
          node {
            id
            title
            metafields(namespace: "app_schema", first: 50) {
              edges {
                node {
                  namespace
                  key
                  value
                  type
                }
              }
            }
          }
        }
      }
    }
    """

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    resp = requests.post(
        "https://{}/admin/api/2025-10/graphql.json".format(shop),
        json={"query": query},
        headers=headers
    )

    if resp.status_code != 200:
        return {
            "error": "Failed to fetch metafields",
            "details": resp.text
        }, 400

    return resp.json()



@app.route("/get_app_schema_metafield", methods=["GET"])
def get_app_schema_metafield():
    print("=== Incoming /get_app_schema_metafield Request ===")
    
    shop = request.args.get("shop")
    gid = request.args.get("gid")

    print(f"[Input] shop={shop}")
    print(f"[Input] gid={gid}")

    if not shop or not gid:
        print("[Error] Missing shop or gid param")
        return jsonify({"error": "Missing shop or gid"}), 400

    # Lookup store access token
    store = StoreToken.query.filter_by(shop=shop).first()

    if not store:
        print("[Error] No store record found.")
        return jsonify({"error": "Store not registered"}), 400

    if not store.access_token:
        print("[Error] Store record found but missing access_token.")
        return jsonify({"error": "Missing access token"}), 400

    token = store.access_token
    print(f"[Store] Found access token for shop={shop}")

    # Decide metafield key based on gid prefix
    metafield_key = None
    if "gid://shopify/Product/" in gid:
        metafield_key = "prod_schema"
    elif "gid://shopify/Collection/" in gid:
        metafield_key = "coll_schema"
    elif "gid://shopify/Article/" in gid or "gid://shopify/Blog/" in gid:
        metafield_key = "blog_schema"
    elif "gid://shopify/Page/" in gid:
        metafield_key = "page_schema"
    else:
        print(f"[Error] Could not determine metafield key from gid={gid}")
        return jsonify({"error": "Invalid or unsupported gid"}), 400

    print(f"[Metafield] Using key={metafield_key}")

    # Query with all node types so Shopify routes correctly
    query = """
    query getAppSchema($id: ID!) {
      node(id: $id) {
        ... on Product  { metafield(namespace:"app_schema", key:"prod_schema") { value } }
        ... on Collection { metafield(namespace:"app_schema", key:"coll_schema") { value } }
        ... on Blog { metafield(namespace:"app_schema", key:"blog_schema") { value } }
        ... on Article { metafield(namespace:"app_schema", key:"blog_schema") { value } }
        ... on Page { metafield(namespace:"app_schema", key:"page_schema") { value } }
      }
    }
    """

    print("[GraphQL] Sending query to Shopify…")
    print(f"[GraphQL] Variables: id={gid}")

    response = graphql_request(shop, token, query, {"id": gid})

    print("[GraphQL] Raw Response:")
    print(response)

    # Shopify returns errors array sometimes
    if "errors" in response:
        print("[Shopify Error] -------------------------")
        print(response["errors"])
        print("----------------------------------------")
        return jsonify(response), 200

    node = response.get("data", {}).get("node")

    if not node:
        print("[GraphQL] Node is null. Shopify did not recognize this GID.")
        print(f"[Possible Cause] Invalid resource type in gid={gid}")
        return jsonify({
            "error": "Node not found for this GID",
            "gid": gid,
        }), 404

    # Try to find metafield on node
    metafield = None
    for key in ["prod_schema", "coll_schema", "blog_schema", "page_schema"]:
        if node.get("metafield") and node["metafield"]["value"]:
            metafield = node["metafield"]
            print(f"[Metafield] Found matching metafield={key}")
            break

    if not metafield:
        print("[Metafield] No metafield found for this object.")
        return jsonify({
            "data": {
                "metafield": None
            }
        }), 200

    print("[Success] Returning metafield value.")
    return jsonify({
        "data": {
            "metafield": metafield
        }
    }), 200



# Store or retain logs external to shopify's base options?
if __name__ == "__main__":
    app.run(debug=True, port=5000)
