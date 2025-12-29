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

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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


# ---------------- DASHBOARD ----------------
# store the latest dynamic values from Shopify
latest_values = {
    "hmac": None,
    "id_token": None
}
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



def get_schema_config_entry(shop: str, access_token: str, schema_type: str):
    query = """
    query GetSchemaConfig($type: String!) {
      metaobjects(type: "schema_config", first: 10) {
        edges {
          node {
            id
            fields {
              key
              value
            }
          }
        }
      }
    }
    """

    resp = shopify_graphql(shop, access_token, query, {"type": schema_type})

    edges = resp["data"]["metaobjects"]["edges"]

    for edge in edges:
        fields = edge["node"]["fields"]
        for f in fields:
            if f["key"] == "schema_type" and f["value"] == schema_type:
                return edge["node"]

    return None

def parse_schema_metaobject(node):
    """
    Turns Shopify metaobject fields[] into:
    {
      "schema_type": "...",
      "mappings": [...]
    }
    """
    if not node:
        return {}

    result = {}

    for field in node.get("fields", []):
        key = field["key"]
        value = field["value"]

        if key == "mappings":
            try:
                value = json.loads(value)
            except Exception:
                value = []

        result[key] = value

    return result



@app.route("/")
def home():
    shop = session.get("shop") or request.args.get("shop")
    hmac = session.get("hmac") or request.args.get("hmac")
    id_token = session.get("id_token") or request.args.get("id_token")

    latest_values["hmac"] = hmac
    latest_values["id_token"] = id_token

    store = StoreToken.query.filter_by(shop=shop).first()
    access_token = store.access_token if store else None

    product_metafields = []
    collection_metafields = []
    product_config = {}
    collection_config = {}

    page_metafields = []
    blog_metafields = []
    page_config = {}
    blog_config = {}

    if access_token:
        try:
            # --------------------------------------------------
            # Metafield definitions (UNCHANGED)
            # --------------------------------------------------
            meta_data = get_metafield_definitions(shop, access_token)
            product_metafields = meta_data["data"]["productDefinitions"]["edges"]
            collection_metafields = meta_data["data"]["collectionDefinitions"]["edges"]
            page_metafields = meta_data["data"]["pageDefinitions"]["edges"]
            blog_metafields = meta_data["data"]["blogDefinitions"]["edges"]

            # --------------------------------------------------
            # FETCH CONFIG FIELDS (UNCHANGED)
            # --------------------------------------------------
            raw_product = fetch_schema_config_entry(
                shop, access_token, "product_schema_mappings"
            )

            raw_collection = fetch_schema_config_entry(
                shop, access_token, "collection_schema_mappings"
            )


            raw_page = fetch_schema_config_entry(
                shop, access_token, "page_schema_mappings"
            )
            
            raw_blog = fetch_schema_config_entry(
                shop, access_token, "blog_schema_mappings"
            )
            print("PRODUCT CONFIG (raw):", raw_product)
            print("COLLECTION CONFIG (raw):", raw_collection)
            print("PAGE CONFIG (raw):", raw_page)
            print("BLOG CONFIG (raw):", raw_blog)

            # --------------------------------------------------
            # NORMALIZATION (FIELD-SAFE, LEGACY-SAFE)
            # --------------------------------------------------
            def normalize(value, key):
                if not isinstance(value, dict):
                    return []

                # direct list
                if isinstance(value.get(key), list):
                    return value[key]

                # legacy nested object
                while isinstance(value, dict) and key in value:
                    value = value.get(key)
                    if isinstance(value, list):
                        return value

                return []


            # --------------------------------------------------
            # PAGE CONFIG (UNCHANGED)
            # --------------------------------------------------
            page_config = {
                "page_schema_mappings": normalize(raw_page, "page_schema_mappings")
            }
            # --------------------------------------------------
            # BLOG CONFIG (UNCHANGED)
            # --------------------------------------------------
            blog_config = {
                "blog_schema_mappings": normalize(raw_blog, "blog_schema_mappings")
            }
            # --------------------------------------------------
            # PRODUCT CONFIG (UNCHANGED)
            # --------------------------------------------------
            product_config = {
                "product_schema_mappings": normalize(
                    raw_product, "product_schema_mappings"
                )
            }

            # --------------------------------------------------
            # COLLECTION CONFIG (FIXED — fallback to product blob)
            # --------------------------------------------------
            collection_config = {
                "collection_schema_mappings": (
                    normalize(raw_collection, "collection_schema_mappings")
                    or normalize(raw_product, "collection_schema_mappings")
                )
            }

        except Exception as e:
            print("Error fetching metafield definitions or config entry:", str(e))

    # --------------------------------------------------
    # Organization schema fields (UNCHANGED)
    # --------------------------------------------------
    org_fields = fetch_organization_schema_properties()

    schemas = [
        {"title": "Organization Schema", "url": "/app/organization-schema-builder"},
        {"title": "Product Schema", "url": "/app/products-schema-builder"},
        {"title": "Collection Schema", "url": "/app/collections-schema-builder"},
        {"title": "Blog Schema", "url": "/app/blog-schema-builder"},
    ]

    print("PRODUCT CONFIG (normalized):", product_config)
    print("COLLECTION CONFIG (normalized):", collection_config)
    print("PAGE CONFIG (normalized):", page_config)
    print("BLOG CONFIG (normalized):", blog_config)

    return render_template(
        "schema_dashboard.html",
        schemas=schemas,
        title="Schema App Dashboard",
        shop_name=shop,
        hmac_value=hmac,
        id_token_value=id_token,
    
        product_metafields=product_metafields,
        collection_metafields=collection_metafields,
        page_metafields=page_metafields,
        blog_metafields=blog_metafields,
    
        org_schema_fields=org_fields,
    
        product_config=product_config,
        collection_config=collection_config,
        page_config=page_config,
        blog_config=blog_config
    )





    
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
            type { name }
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
            type { name }
            description
          }
        }
      }

      pageDefinitions: metafieldDefinitions(ownerType: PAGE, first: 200) {
        edges {
          node {
            id
            name
            namespace
            key
            type { name }
            description
          }
        }
      }

      blogDefinitions: metafieldDefinitions(ownerType: BLOG, first: 200) {
        edges {
          node {
            id
            name
            namespace
            key
            type { name }
            description
          }
        }
      }
    }
    """
    return query_shopify_graphql(shop, access_token, query)



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


def fetch_schema_config_entry(shop, access_token, schema_type):
    """
    Returns a parsed config value for the requested schema_type.

    schema_type should be one of:
      - "product_schema_mappings"
      - "collection_schema_mappings"

    Returns:
      [] or {} if missing
    """

    query = """
    query {
      metaobjects(type: "app_config", first: 1) {
        edges {
          node {
            id
            fields {
              key
              value
            }
          }
        }
      }
    }
    """

    resp = query_shopify_graphql(shop, access_token, query)

    edges = resp.get("data", {}).get("metaobjects", {}).get("edges", [])
    if not edges:
        return []

    fields = edges[0]["node"].get("fields", [])

    for f in fields:
        if f.get("key") == schema_type:
            try:
                return json.loads(f.get("value") or "[]")
            except Exception:
                return []

    return []


def update_metaobject_entry(shop, access_token, config_id, fields):
    try:
        logging.info(
            "Updating metaobject entry %s with fields: %s",
            config_id,
            json.dumps(fields, indent=2)
        )

        # --- Build GraphQL URL dynamically ---
        graphql_url = f"https://{shop}/admin/api/2025-10/graphql.json"
        logging.info("Using Shopify GraphQL URL: %s", graphql_url)

        # --- Properly encode fields for GraphQL ---
        fields_json = json.dumps(fields)  # safe JSON string
        mutation = """
        mutation {
            metaobjectUpdate(
                id: "%s",
                input: %s
            ) {
                metaobject {
                    id
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """ % (config_id, fields_json)

        logging.info("GraphQL mutation prepared: %s", mutation)

        # --- Send request ---
        response = requests.post(
            graphql_url,
            headers={
                "X-Shopify-Access-Token": access_token,
                "Content-Type": "application/json"
            },
            json={"query": mutation}
        ).json()

        # --- Check for errors ---
        user_errors = response.get("data", {}).get("metaobjectUpdate", {}).get("userErrors")
        if user_errors:
            logging.error("User errors updating metaobject: %s", user_errors)
            raise Exception(f"User errors updating metaobject: {user_errors}")

        logging.info("Metaobject entry %s updated successfully.", config_id)
        return response

    except Exception as e:
        logging.error("Failed to update metaobject entry %s: %s", config_id, e, exc_info=True)
        raise



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
def fetch_collection_metafields(shop, access_token, collection_id):
    """
    Fetch all metafields for a collection via REST API.
    Returns a dict of {namespace.key: value}
    """
    url = f"https://{shop}/admin/api/2026-01/collections/{collection_id}/metafields.json"
    headers = {"X-Shopify-Access-Token": access_token}

    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    metafields = resp.json().get("metafields", [])

    mf_dict = {}
    for mf in metafields:
        key = f"{mf['namespace']}.{mf['key']}"
        mf_dict[key] = mf.get("value")

    return mf_dict

def fetch_all_collections(shop, access_token):
    """Fetch all collections (custom + smart) with GraphQL pagination."""
    url = f"https://{shop}/admin/api/2026-01/graphql.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    collections = []
    cursor = None

    while True:
        query = """
        query ($cursor: String) {
          collections(first: 100, after: $cursor) {
            pageInfo { hasNextPage }
            edges {
              cursor
              node {
                id
                title
                handle
                description
                updatedAt
              }
            }
          }
        }
        """

        resp = requests.post(
            url,
            json={"query": query, "variables": {"cursor": cursor}},
            headers=headers
        )
        resp.raise_for_status()

        data = resp.json()["data"]["collections"]

        for edge in data["edges"]:
            collections.append(edge["node"])

        if not data["pageInfo"]["hasNextPage"]:
            break

        cursor = data["edges"][-1]["cursor"]

    return collections

def upsert_collection_app_metafield(shop, access_token, collection_gid, value_dict):
    """
    Create or update app_schema collection metafield using REST RMW pattern.
    """
    METAFIELD_NAMESPACE = "app_schema"
    METAFIELD_KEY = "collection_schema"

    # Parse GID
    try:
        parts = [p for p in collection_gid.split("/") if p]
        # ["gid:", "shopify", "Collection", "12345"]
        if len(parts) != 4 or parts[0] != "gid:":
            raise ValueError()
        resource_type = parts[2].lower()  # collection
        resource_id = parts[3]
    except Exception:
        raise ValueError("Invalid collection_gid format")

    # RMW Step 1: Read
    existing = _find_metafield_by_key_rest(
        shop, access_token, resource_type, resource_id,
        METAFIELD_NAMESPACE, METAFIELD_KEY
    )

    if existing:
        metafield_id = existing["id"]

        try:
            current_data = json.loads(existing.get("value") or "{}")
        except:
            current_data = {}

        merged = current_data.copy()
        merged.update(value_dict)
        final_json = json.dumps(merged)

        url = f"https://{shop}/admin/api/2026-01/{resource_type}s/{resource_id}/metafields/{metafield_id}.json"
        method = requests.put
        log = "Updated"

    else:
        final_json = json.dumps(value_dict)
        url = f"https://{shop}/admin/api/2026-01/{resource_type}s/{resource_id}/metafields.json"
        method = requests.post
        log = "Created"

    payload = {
        "metafield": {
            "type": "json",
            "namespace": METAFIELD_NAMESPACE,
            "key": METAFIELD_KEY,
            "value": final_json
        }
    }

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    resp = method(url, headers=headers, json=payload)
    resp.raise_for_status()

    logging.info(f"{log} {METAFIELD_NAMESPACE}.{METAFIELD_KEY} for {collection_gid}")

    return resp.json()
    
def extract_collection_attribute(collection_data, attr_path):
    # support collection.x
    if attr_path.startswith("collection."):
        attr_path = attr_path.replace("collection.", "", 1)

    try:
        if "." not in attr_path:
            return collection_data.get(attr_path, "")
        parts = attr_path.split(".")
        val = collection_data
        for p in parts:
            val = val.get(p, "")
        return val
    except Exception:
        return ""

def build_collection_schema_from_mappings(collection_data, existing_mfs, mappings):
    schema_json = {}

    for mapping in mappings:
        schema_field = mapping.get("schemaField")
        source_field = mapping.get("sourceField")

        if not schema_field or not source_field:
            continue

        # metafields
        if source_field.startswith("collection.metafield: "):
            mf_key = source_field.replace("collection.metafield: ", "").strip()
            value = existing_mfs.get(mf_key, "")
        else:
            # collection attributes
            value = extract_collection_attribute(collection_data, source_field)
            if value is None:
                value = ""

        schema_json[schema_field] = value

    return schema_json


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

# --- Helper to fetch all existing product metafields ---
def fetch_product_metafields(shop, access_token, product_id):
    """
    Fetch all metafields for a product via REST API.
    Returns a dict of {namespace.key: value} for easy mapping.
    """
    url = f"https://{shop}/admin/api/2026-01/products/{product_id}/metafields.json"
    headers = {"X-Shopify-Access-Token": access_token}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    metafields = resp.json().get("metafields", [])
    
    mf_dict = {}
    for mf in metafields:
        key = f"{mf['namespace']}.{mf['key']}"
        mf_dict[key] = mf.get("value")
    return mf_dict


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
    
    try:
        parts = owner_gid.split("/")
        # remove empty elements caused by double slashes
        parts = [p for p in parts if p]
    
        # expected: ["gid:", "shopify", "Product", "8085504262319"]
        if len(parts) != 4 or parts[0] != "gid:":
            raise ValueError()
    
        resource_type = parts[2].lower()
        resource_id = parts[3]
    except Exception:
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
        final_json_string = json.dumps(value_dict)
        
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
    """Fetch full product objects (title, vendor, etc) using GraphQL pagination."""
    url = f"https://{shop}/admin/api/2026-01/graphql.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

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
                        title
                        vendor
                        handle
                        description
                        bodyHtml
                        status
                        tags
                        createdAt
                        updatedAt
                    }
                }
            }
        }
        """

        resp = requests.post(
            url,
            json={"query": query, "variables": {"cursor": cursor}},
            headers=headers
        )
        resp.raise_for_status()

        data = resp.json()["data"]["products"]

        # append full product objects
        for edge in data["edges"]:
            products.append(edge["node"])

        if not data["pageInfo"]["hasNextPage"]:
            break

        cursor = data["edges"][-1]["cursor"]

    return products


def build_app_schema_json(schema_definition, existing_mfs, mappings):
    """
    schema_definition: {field_name: type}  (string/number/boolean)
    existing_mfs: {namespace.key: value}  actual Shopify metafield values
    mappings: {namespace.key: schema_field_name} frontend mapping

    Returns full JSON with populated values for upsert.
    """
    schema_json = {}

    # Start with defaults
    for field_key, field_type in schema_definition.items():
        if field_type == "string":
            schema_json[field_key] = ""
        elif field_type == "number":
            schema_json[field_key] = 0
        elif field_type == "boolean":
            schema_json[field_key] = False
        else:
            schema_json[field_key] = None

    # Overwrite defaults with actual Shopify metafield values based on frontend mapping
    for mf_key, schema_field in mappings.items():
        if schema_field and mf_key in existing_mfs:
            schema_json[schema_field] = existing_mfs[mf_key]

    return schema_json



def build_schema_from_mappings(product_data, existing_mfs, mappings):
    """
    Build a schema JSON containing fields selected on the frontend.
    Ensures that product attributes like 'title' are always included, even if empty.
    """
    schema_json = {}

    for mapping in mappings:
        schema_field = mapping.get("schemaField")
        source_field = mapping.get("sourceField")
        if not schema_field or not source_field:
            continue

        value = None

        if source_field.startswith("metafield: "):
            mf_key = source_field.replace("metafield: ", "").strip()
            value = existing_mfs.get(mf_key, "")
        else:
            # Handle standard product attributes
            value = extract_product_attribute(product_data, source_field)
            # Force inclusion: if value is None, default to empty string
            if value is None:
                value = ""

        schema_json[schema_field] = value

    return schema_json



def extract_product_attribute(product_data, attr_path):
    # Support `product.x` syntax even though product_data has no `product` root
    if attr_path.startswith("product."):
        attr_path = attr_path.replace("product.", "", 1)

    try:
        # simple top-level attribute
        if "." not in attr_path:
            return product_data.get(attr_path, "")
        # nested future-proofing
        parts = attr_path.split(".")
        value = product_data
        for p in parts:
            value = value.get(p, "")
        return value
    except Exception:
        return ""


def wrap_flattened_json_in_schema(flattened_json):
    """
    Takes a dict and wraps it in a minimal schema.org Product structure
    """
    schema_wrapped = {
        "@context": "http://schema.org/",
        "@type": "Product"
    }

    # Merge flattened JSON inside
    schema_wrapped.update(flattened_json)

    return schema_wrapped


def load_schema_mappings(shop, access_token, schema_type):
    """
    Load mappings JSON for a given schema_type.
    """
    entry = get_schema_config_entry(shop, access_token, schema_type)
    if not entry:
        return []

    raw = entry.get("mappings", {}).get("value")
    if not raw:
        return []

    return json.loads(raw)


def update_schema_mappings(shop, access_token, schema_type, mappings):
    """
    Replace the mappings for a given schema_type.
    """
    entry = get_schema_config_entry(shop, access_token, schema_type)
    if not entry:
        entry_id = ensure_schema_config_entry(shop, access_token, schema_type)
    else:
        entry_id = entry["id"]

    mappings_json = json.dumps(mappings)
    quoted = json.dumps(mappings_json)

    mutation = """
    mutation {{
      metaobjectUpdate(
        id: "{entry_id}"
        metaobject: {{
          fields: [
            {{ key: "mappings", value: {quoted} }}
          ]
        }}
      ) {{
        metaobject {{ id }}
        userErrors {{ field message }}
      }}
    }}
    """.format(entry_id=entry_id, quoted=quoted)

    resp = query_shopify_graphql(shop, access_token, mutation)
    node = resp.get("data", {}).get("metaobjectUpdate", {})

    if node.get("userErrors"):
        raise Exception("Metaobject update errors: {}".format(node["userErrors"]))

    return entry_id

def ensure_schema_config_entry(shop, access_token, schema_type):
    """
    Ensures the SINGLE schema_config metaobject exists.
    Returns the metaobject ID.
    """

    # --- Fetch ANY existing config entry (ignore schema_type) ---
    entry = get_schema_config_entry(shop, access_token)
    if entry:
        return entry["id"]

    logging.info("No schema_config metaobject found, creating singleton entry...")

    # --- Create ONE global entry ---
    new_entry_data = {
        "product_schema_mappings": [],
        "collection_schema_mappings": []
    }

    resp = create_config_entry(shop, access_token, new_entry_data)

    node = resp.get("data", {}).get("metaobjectCreate")
    if not node or node.get("userErrors"):
        raise Exception(
            f"Failed to create schema config entry: "
            f"{node.get('userErrors') if node else resp}"
        )

    logging.info(
        "Created SINGLE schema config entry with ID %s",
        node["metaobject"]["id"]
    )

    return node["metaobject"]["id"]



def get_schema_config_entry(shop, access_token, schema_type):
    """
    Fetch the metaobject entry for the given schema_type.
    Returns None if it does not exist or the field is missing.
    """
    query = """
    {
      metaobjects(type: "app_schema", first: 10) {
        nodes {
          id
          schema_type: field(key: "schema_type") { value }
          mappings: field(key: "mappings") { value }
        }
      }
    }
    """
    resp = query_shopify_graphql(shop, access_token, query)
    nodes = resp.get("data", {}).get("metaobjects", {}).get("nodes", [])

    for node in nodes:
        schema_field = node.get("schema_type")
        if schema_field is None:
            logging.warning("Skipping metaobject {}: missing schema_type".format(node.get("id")))
            continue
        if schema_field.get("value") == schema_type:
            return node

    return None




def ensure_metaobject_definition(shop, access_token):
    """
    Ensures the app_schema metaobject definition exists.
    """
    query = """
    query {
      metaobjectDefinitionByType(type: "app_schema") {
        id
      }
    }
    """

    resp = query_shopify_graphql(shop, access_token, query)
    existing = resp.get("data", {}).get("metaobjectDefinitionByType")

    if existing and existing.get("id"):
        logging.info(f"Metaobject definition exists: {existing['id']}")
        return existing["id"]

    logging.info("Creating app_schema metaobject definition")

    mutation = """
    mutation {
      metaobjectDefinitionCreate(definition: {
        name: "App Schema Config",
        type: "app_schema",
        fieldDefinitions: [
          {
            name: "Schema Type",
            key: "schema_type",
            type: "single_line_text_field",
            required: true
          },
          {
            name: "Mappings",
            key: "mappings",
            type: "single_line_text_field",
            required: false
          }
        ]
      }) {
        metaobjectDefinition { id }
        userErrors { field message }
      }
    }
    """

    resp = query_shopify_graphql(shop, access_token, mutation)
    node = resp.get("data", {}).get("metaobjectDefinitionCreate", {})

    if node.get("userErrors"):
        raise Exception(f"Metaobject definition errors: {node['userErrors']}")

    return node["metaobjectDefinition"]["id"]

def ensure_app_config_definition(shop, access_token):
    query = """
    query {
      metaobjectDefinitionByType(type: "app_config") {
        id
      }
    }
    """
    resp = query_shopify_graphql(shop, access_token, query)
    existing = resp.get("data", {}).get("metaobjectDefinitionByType")
    
    if existing and existing.get("id"):
        return existing["id"]

    # Create the definition
    mutation = """
    mutation {
      metaobjectDefinitionCreate(definition: {
        name: "App Config",
        type: "app_config",
        fieldDefinitions: [
          { key: "product_schema_mappings", name: "Product Schema Mappings", type: "json" },
          { key: "collection_schema_mappings", name: "Collection Schema Mappings", type: "json" }
        ]
      }) {
        metaobjectDefinition { id }
        userErrors { field message }
      }
    }
    """
    resp = query_shopify_graphql(shop, access_token, mutation)
    node = resp.get("data", {}).get("metaobjectDefinitionCreate", {})

    if node.get("userErrors"):
        raise Exception(f"Metaobject definition creation errors: {node['userErrors']}")

    return node["metaobjectDefinition"]["id"]

def ensure_config_entry(shop, access_token, metaobject_type, field_mappings=None):
    HANDLE = "global"

    # ------------------------------------------------------------------
    # 1️⃣ Look up existing metaobject by HANDLE (this prevents duplicates)
    # ------------------------------------------------------------------
    query = """
    {{
      metaobjectByHandle(type: "{type}", handle: "{handle}") {{
        id
      }}
    }}
    """.format(
        type=metaobject_type,
        handle=HANDLE
    )

    resp = query_shopify_graphql(shop, access_token, query)
    node = resp.get("data", {}).get("metaobjectByHandle")

    if node and node.get("id"):
        logging.info("Reusing existing app_config metaobject: %s", node["id"])
        return node["id"]

    logging.info("No existing app_config metaobject found — creating one")

    # ------------------------------------------------------------------
    # 2️⃣ Build fields payload (JSON-safe)
    # ------------------------------------------------------------------
    fields_parts = []

    if field_mappings:
        for key, value in field_mappings.items():
            value_json = json.dumps(value)
            fields_parts.append(
                '{{ key: "{key}", value: {value} }}'.format(
                    key=key,
                    value=json.dumps(value_json)
                )
            )

    fields_str = ", ".join(fields_parts)

    # ------------------------------------------------------------------
    # 3️⃣ Create the SINGLE metaobject with a fixed handle
    # ------------------------------------------------------------------
    mutation = """
    mutation {{
      metaobjectCreate(
        metaobject: {{
          type: "{type}"
          handle: "{handle}"
          fields: [{fields}]
        }}
      ) {{
        metaobject {{ id }}
        userErrors {{ field message }}
      }}
    }}
    """.format(
        type=metaobject_type,
        handle=HANDLE,
        fields=fields_str
    )

    resp = query_shopify_graphql(shop, access_token, mutation)
    result = resp.get("data", {}).get("metaobjectCreate")

    if not result:
        raise Exception("Metaobject create failed: {}".format(resp))

    if result.get("userErrors"):
        raise Exception("Metaobject create errors: {}".format(result["userErrors"]))

    metaobject_id = result["metaobject"]["id"]
    logging.info("Created new app_config metaobject: %s", metaobject_id)

    return metaobject_id




def merge_and_update_config(shop, access_token, schema_type, new_mappings):
    """
    Fetches existing schema_config entry, merges new mappings, and updates it.
    Returns the metaobject ID.
    """
    entry = get_schema_config_entry(shop, access_token, schema_type)

    if entry:
        # Merge existing mappings with new_mappings
        parsed = parse_schema_metaobject(entry)
        existing_mappings = parsed.get("mappings", [])
        merged = existing_mappings.copy()
        merged.extend(new_mappings)
        merged = [dict(t) for t in {tuple(d.items()) for d in merged}]  # deduplicate
        update_schema_mappings(shop, access_token, schema_type, merged)
        return entry["id"]

    # Entry does not exist → create it
    return ensure_schema_config_entry(shop, access_token, schema_type)




def get_config_metaobject_entry(shop, access_token):
    query = """
    {
      metaobjects(type: "app_schema", first: 1) {
        nodes {
          id
          product_schema_mappings: field(key: "product_schema_mappings") { value }
        }
      }
    }
    """
    resp = query_shopify_graphql(shop, access_token, query)
    nodes = resp.get("data", {}).get("metaobjects", {}).get("nodes", [])
    return nodes[0] if nodes else None

def create_config_entry(shop, access_token, mappings_json):
    mappings_str = json.dumps(mappings_json)
    quoted = json.dumps(mappings_str)

    mutation = (
        "mutation {"
        "  metaobjectCreate(metaobject: {"
        '    type: "app_config"'
        "    fields: ["
        "      {"
        '        key: "product_schema_mappings"'
        "        value: " + quoted +
        "      }"
        "    ]"
        "  }) {"
        "    metaobject { id }"
        "    userErrors { field message }"
        "  }"
        "}"
    )
    return query_shopify_graphql(shop, access_token, mutation)


def update_config_entry(shop, access_token, entry_id, mappings_json, field_key=None):
    """
    Update the config metaobject.
    - If field_key is provided, only update that field
    - If field_key is None, update all fields in mappings_json
    """
    quoted_id = json.dumps(entry_id)[1:-1]

    # Build fields array
    if field_key:
        fields = [{"key": field_key, "value": json.dumps(mappings_json)}]
    else:
        fields = [{"key": k, "value": json.dumps(v)} for k, v in mappings_json.items()]

    # Convert fields to GraphQL string
    fields_str = ", ".join(
        f'{{ key: "{f["key"]}", value: {f["value"]} }}' for f in fields
    )

    mutation = (
        f'mutation {{'
        f'  metaobjectUpdate(id: "{quoted_id}", metaobject: {{ fields: [{fields_str}] }}) {{'
        f'    metaobject {{ id }}'
        f'    userErrors {{ field message }}'
        f'  }}'
        f'}}'
    )

    return query_shopify_graphql(shop, access_token, mutation)



def fetch_metaobject_fields(shop, access_token, config_id):
    """
    Fetch existing fields from a Shopify metaobject (app_config).
    Returns a dict: { field_key: value } with JSON-decoded values.
    """
    query = """
    query getMetaobject($id: ID!) {
      metaobject(id: $id) {
        id
        fields {
          key
          value
        }
      }
    }
    """
    variables = {"id": config_id}
    response = graphql_request(shop, access_token, query, variables)

    if "errors" in response:
        raise Exception(f"GraphQL errors fetching metaobject: {response['errors']}")

    node = response.get("data", {}).get("metaobject")
    if not node:
        return {}

    fields = {}
    for f in node.get("fields", []):
        key = f.get("key")
        value = f.get("value")
        try:
            # decode JSON if possible
            value = json.loads(value)
        except Exception:
            pass
        fields[key] = value

    return fields

def list_all_metaobjects(shop, access_token, metaobject_type):
    """
    Returns a list of all metaobjects of the given type.
    Each item is a dict with at least 'id' and 'handle'.
    """
    query = """
    query listMetaobjects($type: String!, $first: Int!, $after: String) {
      metaobjects(first: $first, type: $type, after: $after) {
        edges {
          node {
            id
            handle
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """

    result = []
    after = None
    headers = {
        "X-Shopify-Access-Token": access_token,
        "Content-Type": "application/json"
    }

    while True:
        variables = {"type": metaobject_type, "first": 50, "after": after}
        resp = requests.post(
            f"https://{shop}/admin/api/2025-10/graphql.json",
            headers=headers,
            json={"query": query, "variables": variables}
        )
        resp.raise_for_status()
        data = resp.json()
        edges = data["data"]["metaobjects"]["edges"]
        for edge in edges:
            result.append(edge["node"])
        page_info = data["data"]["metaobjects"]["pageInfo"]
        if page_info["hasNextPage"]:
            after = page_info["endCursor"]
        else:
            break

    return result

def delete_metaobject(shop, access_token, metaobject_id):
    query = """
    mutation metaobjectDelete($id: ID!) {
      metaobjectDelete(id: $id) {
        userErrors {
          field
          message
        }
      }
    }
    """
    variables = {"id": metaobject_id}
    url = f"https://{shop}/admin/api/2025-10/graphql.json"
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token,
    }
    response = requests.post(url, json={"query": query, "variables": variables}, headers=headers)
    data = response.json()

    errors = data.get("data", {}).get("metaobjectDelete", {}).get("userErrors", [])
    if errors:
        print(f"Failed to delete metaobject {metaobject_id} errors:", errors)
    else:
        print(f"Deleted metaobject: {metaobject_id}")


def dedupe_mappings(mappings):
    seen = set()
    deduped = []

    for m in mappings:
        if not isinstance(m, dict):
            continue

        key = (m.get("schemaField"), m.get("sourceField"))
        if key in seen:
            continue

        seen.add(key)
        deduped.append(m)

    return deduped



@app.route("/verify_and_create_metafields", methods=["POST"])
def verify_and_create_metafields():
    data = request.json
    logging.info("INPUT (products & collections): %s", json.dumps(data, indent=2))

    shop = data.get("shop") or session.get("shop")
    access_token = get_access_token_for_shop(shop)
    if not access_token:
        return jsonify({"error": "No access token for shop"}), 400

    incoming_product = data.get("product_schema_mappings")
    incoming_collection = data.get("collection_schema_mappings")
    incoming_page = data.get("page_schema_mappings")
    incoming_blog = data.get("blog_schema_mappings")
    existing_product = fetch_schema_config_entry(shop, access_token, "product_schema_mappings")
    existing_collection = fetch_schema_config_entry(shop, access_token, "collection_schema_mappings")
    existing_product = fetch_schema_config_entry(shop, access_token, "page_schema_mappings")
    existing_collection = fetch_schema_config_entry(shop, access_token, "blog_schema_mappings")
    # ------------------------------------------------------------------
    # Ensure metaobject definition exists
    # ------------------------------------------------------------------
    ensure_metaobject_definition(shop, access_token)
    metaobject_type = "app_config"

    # ------------------------------------------------------------------
    # NORMALIZATION HELPER (CRITICAL FIX)
    # ------------------------------------------------------------------
    def extract_list(value, key):
        """
        Safely extracts a list from legacy / nested / recursive blobs.
        Always returns a list.
        """
        if isinstance(value, list):
            return value

        if not isinstance(value, dict):
            return []

        # direct hit
        if isinstance(value.get(key), list):
            return value[key]

        # walk legacy nesting
        while isinstance(value, dict) and key in value:
            value = value.get(key)
            if isinstance(value, list):
                return value

        return []

    # ------------------------------------------------------------------
    # STEP 1: Fetch existing schemas (SAFE)
    # ------------------------------------------------------------------
    existing_product = fetch_schema_config_entry(
        shop, access_token, "product_schema_mappings"
    )

    existing_collection = fetch_schema_config_entry(
        shop, access_token, "collection_schema_mappings"
    )

    product_schema_mappings = extract_list(
        existing_product, "product_schema_mappings"
    )

    collection_schema_mappings = extract_list(
        existing_collection, "collection_schema_mappings"
    )

    existing_page = fetch_schema_config_entry(
        shop, access_token, "page_schema_mappings"
    )

    existing_blog = fetch_schema_config_entry(
        shop, access_token, "blog_schema_mappings"
    )

    page_schema_mappings = extract_list(
        existing_product, "page_schema_mappings"
    )

    blog_schema_mappings = extract_list(
        existing_collection, "blog_schema_mappings"
    )
    logging.info("Existing PRODUCT mappings (normalized): %s", json.dumps(product_schema_mappings, indent=2))
    logging.info("Existing COLLECTION mappings (normalized): %s", json.dumps(collection_schema_mappings, indent=2))
    
    logging.info("Existing BLOG mappings (normalized): %s", json.dumps(blog_schema_mappings, indent=2))
    logging.info("Existing PAGE mappings (normalized): %s", json.dumps(page_schema_mappings, indent=2))
    
    # ------------------------------------------------------------------
    # STEP 2: Merge incoming payload (NORMALIZED)
    # ------------------------------------------------------------------
    if incoming_product is not None:
        product_schema_mappings = extract_list(
            incoming_product, "product_schema_mappings"
        )

    if incoming_collection is not None:
        collection_schema_mappings = extract_list(
            incoming_collection, "collection_schema_mappings"
        )
    if incoming_page is not None:
        page_schema_mappings = extract_list(
            incoming_page, "page_schema_mappings"
        )

    if incoming_blog is not None:
        blog_schema_mappings = extract_list(
            incoming_blog, "blog_schema_mappings"
        )
    logging.info(
        "Merged schema state (FLAT): %s",
        json.dumps({
            "product_schema_mappings": product_schema_mappings,
            "collection_schema_mappings": collection_schema_mappings,
            "page_schema_mappings": page_schema_mappings,
            "blog_schema_mappings": blog_schema_mappings
        }, indent=2)
    )

    # ------------------------------------------------------------------
    # STEP 3: Delete all existing entries (UNCHANGED)
    # ------------------------------------------------------------------
    existing_entries = list_all_metaobjects(shop, access_token, metaobject_type)
    for entry in existing_entries:
        delete_metaobject(shop, access_token, entry["id"])
        logging.info("Deleted config entry: %s", entry["id"])

    # ------------------------------------------------------------------
    # STEP 4: Create single clean entry (FIXED)
    # ------------------------------------------------------------------
    product_schema_mappings = dedupe_mappings(product_schema_mappings)
    collection_schema_mappings = dedupe_mappings(collection_schema_mappings)
    page_schema_mappings = dedupe_mappings(page_schema_mappings)
    blog_schema_mappings = dedupe_mappings(blog_schema_mappings)
    resp = create_config_entry(
        shop,
        access_token,
        {
            "schema_type": metaobject_type,
            "product_schema_mappings": product_schema_mappings,
            "collection_schema_mappings": collection_schema_mappings,
            "page_schema_mappings": page_schema_mappings,
            "blog_schema_mappings": blog_schema_mappings
        }
    )


    node = resp.get("data", {}).get("metaobjectCreate")
    if not node or node.get("userErrors"):
        raise Exception("Failed to create config entry")

    logging.info("Created new config entry: %s", node["metaobject"]["id"])

    # ------------------------------------------------------------------
    # STEP 5: Background jobs (UNCHANGED)
    # ------------------------------------------------------------------
    def process_products():
        products = fetch_all_products(shop, access_token)
        for product in products:
            existing_mfs = fetch_product_metafields(
                shop, access_token, product["id"].split("/")[-1]
            )
            schema_json = build_schema_from_mappings(
                product, existing_mfs, product_schema_mappings
            )
            schema_json = wrap_flattened_json_in_schema(schema_json)
            upsert_app_metafield(shop, access_token, product["id"], schema_json)

    def process_collections():
        collections = fetch_all_collections(shop, access_token)
        for col in collections:
            existing_mfs = fetch_collection_metafields(
                shop, access_token, col["id"].split("/")[-1]
            )
            schema_json = build_schema_from_mappings(
                col, existing_mfs, collection_schema_mappings
            )
            schema_json = wrap_flattened_json_in_schema(schema_json)
            upsert_collection_app_metafield(shop, access_token, col["id"], schema_json)

    threading.Thread(target=process_products, daemon=True).start()
    threading.Thread(target=process_collections, daemon=True).start()

    return jsonify({"message": "Schema saved and site-wide metafields updating"})




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
