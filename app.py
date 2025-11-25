import os
import requests
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

SCHEMA_CACHE = {
    "timestamp": 0,
    "organization_fields": []
}

# Cache lifetime – 24 hours (in seconds)
CACHE_TTL = 60 * 60 * 24

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Store Locally?
allowed_origins = [
    "https://www.xxx",
    "https://xxx",
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
    token = session.get("access_token")  # Your OAuth token for the store

    if not shop or not token:
        flash("Shop or access token not found.", "error")
        return redirect(url_for("schema_dashboard"))

    # Define metafields for products
    product_metafields = [
        {
            "name": "Ingredients",
            "key": "ingredients",
            "description": "List of ingredients used in the product.",
            "type": "list.single_line_text_field",
            "ownerType": "PRODUCT"
        },
        {
            "name": "Allergens",
            "key": "allergens",
            "description": "Allergens present in the product.",
            "type": "list.single_line_text_field",
            "ownerType": "PRODUCT"
        }
    ]

    # Define metafields for collections
    collection_metafields = [
        {
            "name": "Collection Theme",
            "key": "theme",
            "description": "Theme of the collection.",
            "type": "single_line_text_field",
            "ownerType": "COLLECTION"
        }
    ]

    # Create metafields via GraphQL
    for mf in product_metafields + collection_metafields:
        query = """
        mutation metafieldDefinitionCreate($definition: MetafieldDefinitionInput!) {
          metafieldDefinitionCreate(definition: $definition) {
            createdDefinition {
              id
              name
              namespace
              key
            }
            userErrors {
              field
              message
            }
          }
        }
        """
        variables = {"definition": {
            "name": mf["name"],
            "key": mf["key"],
            "description": mf["description"],
            "type": mf["type"],
            "ownerType": mf["ownerType"],
            "namespace": "$app"  # <-- app-owned namespace
        }}

        resp = graphql_request(shop, token, query, variables)
        errors = resp.get("data", {}).get("metafieldDefinitionCreate", {}).get("userErrors", [])
        if errors:
            print(f"Error creating {mf['name']}: {errors}")

    flash("App-owned metafields created for products and collections!", "success")
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

@app.route("/verify_and_create_metafields", methods=["POST"])
def verify_and_create_metafields():
    data = request.json
    shop = data.get("shop")
    posted_hmac = data.get("hmac")
    id_token = data.get("id_token")
    product_mappings = data.get("product_mappings", {})
    collection_mappings = data.get("collection_mappings", {})

    if not shop or not posted_hmac:
        return jsonify({"error": "Missing shop or HMAC"}), 400

    # Verify HMAC
    if posted_hmac != latest_values.get("hmac"):
        return jsonify({"error": "HMAC mismatch"}), 400

    # Fetch store token
    store = StoreToken.query.filter_by(shop=shop).first()
    if not store or not store.access_token:
        return jsonify({"error": "Store token missing"}), 400
    access_token = store.access_token

    headers = {
        "X-Shopify-Access-Token": access_token,
        "Content-Type": "application/json",
    }

    created_metafields = {"product": None, "collection": None}

    # --- Product schema metafield ---
    if product_mappings:
        product_payload = {
            "metafield": {
                "namespace": "app_schema",
                "key": "product_schema_mappings",
                "type": "json",
                "description": "Product schema → metafield mappings",
                "value": json.dumps(product_mappings)
            }
        }
        try:
            resp = requests.post(f"https://{shop}/admin/api/2026-01/metafields.json",
                                 headers=headers, json=product_payload)
            resp.raise_for_status()
            created_metafields["product"] = resp.json().get("metafield")
        except Exception as e:
            return jsonify({"error": "Failed to create product metafield", "details": str(e)}), 500

    # --- Collection schema metafield ---
    if collection_mappings:
        collection_payload = {
            "metafield": {
                "namespace": "app_schema",
                "key": "collection_schema_mappings",
                "type": "json",
                "description": "Collection schema → metafield mappings",
                "value": json.dumps(collection_mappings)
            }
        }
        try:
            resp = requests.post(f"https://{shop}/admin/api/2026-01/metafields.json",
                                 headers=headers, json=collection_payload)
            resp.raise_for_status()
            created_metafields["collection"] = resp.json().get("metafield")
        except Exception as e:
            return jsonify({"error": "Failed to create collection metafield", "details": str(e)}), 500

    return jsonify({
        "success": True,
        "message": "App-owned metafields created successfully",
        "created_metafields": created_metafields
    })


@app.route("/get_metafields", methods=["POST"])
def get_metafields():
    data = request.json
    shop = data.get("shop")
    hmac = data.get("hmac")
    id_token = data.get("id_token")

    # --- Validate HMAC / ID token here if needed ---
    
    # Get access token for shop (fetch from DB or in-memory)
    access_token = get_access_token_for_shop(shop)
    if not access_token:
        return {"error": "Access token not found"}, 400

    # Query Shopify GraphQL for product and collection metafields
    import requests

    query = """
    {
      products(first: 10) {
        edges {
          node {
            id
            title
            metafields(first: 10) {
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
      collections(first: 10) {
        edges {
          node {
            id
            title
            metafields(first: 10) {
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

    resp = requests.post(f"https://{shop}/admin/api/2025-10/graphql.json", json={"query": query}, headers=headers)
    
    if resp.status_code != 200:
        return {"error": "Failed to fetch metafields", "details": resp.text}, 400

    return resp.json()


# Store or retain logs external to shopify's base options?
if __name__ == "__main__":
    app.run(debug=True, port=5000)
