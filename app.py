import json
import os
import traceback
import logging
import requests
from flask import Flask, request, jsonify
from opencensus.ext.azure.log_exporter import AzureLogHandler

app = Flask(__name__)

logger = logging.getLogger(__name__)

logger.addHandler(AzureLogHandler(
    connection_string='InstrumentationKey=c66ff9a3-15b3-4e22-b7b9-ffd8871211fa;IngestionEndpoint=https://eastus-8.in.applicationinsights.azure.com/;LiveEndpoint=https://eastus.livediagnostics.monitor.azure.com/')
)



graph_user_groups_url = "https://graph.microsoft.com/v1.0/users/{user_id}/transitiveMemberOf/microsoft.graph.group?$count=true&$select=displayName,securityEnabled"
token_endpoint_url = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
tenant_id = os.getenv('TENANT_ID', 'c663f89c-ef9b-418f-bd3d-41e46c0ce068')
client_id = os.getenv('CLIENT_ID', 'a690ad4f-3e04-43dc-94b8-3182da8da6ed')
client_secret = os.getenv('CLIENT_SECRET', '6038Q~FbxJ3kawSPrK9Dp5p_zTE.GIksG8nXPaPp')


def get_email_from_oauth(req_body):
    return req_body['data']['access']['claims']['sub']


def get_email_from_saml(req_body):
    return req_body['data']['context']['user']['profile']['login']


def get_custom_value_from_saml(req_body):
    if 'custom' in req_body['data']['assertion']['claims']:
        return req_body['data']['assertion']['claims']['custom']['attributeValues'][0]['value']
    return ""


def get_response_for_oauth(final_groups_list):
    opt = [{'op': 'add', 'path': "/claims/roles", 'value': final_groups_list},
           {'op': 'remove', 'path': "/claims/azgroups"}]
    return {'commands': [{
        'type': "com.okta.access.patch",
        'value': opt
    }]}


def get_response_for_saml(final_groups_list, custom_value):
    attributeValues = []
    for item in final_groups_list:
        attributeValues.append({
            "attributes": {
                "xsi:type": "xs:string"
            },
            "value": item
        })

    opt = []
    if custom_value:
        opt.append({'op': 'add', 'path': "/claims/" + custom_value, 'value': {
            "attributes": {
                "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
            },
            "attributeValues": attributeValues
        }})
    else:
        opt.append({'op': 'add', 'path': "/claims/groups", 'value': {
            "attributes": {
                "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
            },
            "attributeValues": attributeValues
        }})
    return {'commands': [{
        'type': "com.okta.assertion.patch",
        'value': opt
    }]}


# GET NAME FROM AZURE ENDPOINT
def get_az_groups(azure_user_email):
    if not azure_user_email:
        raise ValueError("Unable to find user email id")

    final_groups_list = []
    token_url = token_endpoint_url.format(tenant=tenant_id)
    logger.debug("Token URL " + token_url)
    token_response = requests.post(
        url=token_url,
        data={
            "client_id": client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        })
    if token_response.status_code != 200:
        logger.info("Unable to retrieve token due to " + str(token_response.status_code))
        logger.debug("Response: " + token_response.text)
        raise ValueError("Unable to get token")

    token_response_data = token_response.json()
    logger.debug("Token Response " + json.dumps(token_response_data))
    access_tk = token_response_data['access_token']
    logger.info("Accessing groups for " + azure_user_email)
    groups_response = requests.get(
        url=graph_user_groups_url.format(user_id=azure_user_email),
        headers={
            "Authorization": "Bearer {access_token}".format(access_token=access_tk)
        })

    if groups_response.status_code != 200:
        logger.info("Unable to retrieve groups due to " + str(groups_response.status_code))
        logger.debug("Response: " + groups_response.text)
        raise ValueError("Unable to get groups")

    groups_response_data = groups_response.json()
    logger.debug("AZ Group Response " + json.dumps(groups_response_data))
    groups_response_data_values = groups_response_data['value']
    for item in groups_response_data_values:
        if item['securityEnabled']:
            final_groups_list.append(item['displayName'])

    return final_groups_list


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


@app.route('/trance', methods=['POST'])
def trance():
    try:
        req_body = request.json
        # logger.info("Processing okta request event id: " + event_id)
        # logger.info("OKTA Request " + json.dumps(req_body))
        context = req_body['data']['context']
        protocol = context['protocol']
        protocol_type = protocol['type']
        azure_user_email = None
        if protocol_type == 'OAUTH2.0':
            azure_user_email = get_email_from_oauth(req_body)
        elif protocol_type == 'SAML2.0':
            azure_user_email = get_email_from_saml(req_body)
        else:
            raise ValueError("The protocol_type " + protocol_type + " not implemented")
        # ---------------------------------------------------------------------- #
        final_groups_list = get_az_groups(azure_user_email)
        # ---------------------------------------------------------------------- #

        response = {}
        if protocol_type == 'OAUTH2.0':
            response = get_response_for_oauth(final_groups_list)
        elif protocol_type == 'SAML2.0':
            response = get_response_for_saml(final_groups_list, get_custom_value_from_saml(req_body))

        logger.debug("Result: " + json.dumps(response))
        return jsonify(response)
    except ValueError:
        traceback.print_exc()
        return jsonify({
            "error": "API Exception for event Id: " + event_id
        }), 500


if __name__ == '__main__':
    app.run(port=8000)
