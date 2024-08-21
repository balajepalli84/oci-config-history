import oci
import json
import logging

# Configure logging
logging.basicConfig(filename=r'C:\Security\Blogs\oci-config-history\logs\logfile.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

config = oci.config.from_file()
tenancy_id = config["tenancy"]
resource_type = 'securitylist'
resource_ocid = 'ocid1.securitylist.oc1.iad.aaaaaaaar2g2yvbay5w6cnpbelb2c3nvnkp7vdkgqu3uyf5v2uf7y3eazl4q'

# Initialize clients
resource_search_client = oci.resource_search.ResourceSearchClient(config)
identity_client = oci.identity.IdentityClient(config)

def search_resource_by_ocid(ocid):
    search_details = oci.resource_search.models.FreeTextSearchDetails(
        type="FreeText",
        text=ocid,
        matching_context_type="HIGHLIGHTS"
    )
    search_response = resource_search_client.search_resources(
        search_details=search_details,
        tenant_id=tenancy_id
    )
    return search_response.data.items

def get_resource_details(ocid):    
    query = f"query {resource_type} resources where identifier='{ocid}'"
    structured_search_details = oci.resource_search.models.StructuredSearchDetails(
        query=query,
        type="Structured",
        matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_NONE
    )   
    search_response = resource_search_client.search_resources(structured_search_details)
    return search_response.data

# Retrieve resource details and associated resources
resource_details = get_resource_details(resource_ocid)
search_results = search_resource_by_ocid(resource_ocid)

# Create a JSON structure
resource_data = {
    "resource_details": {
        "display_name": resource_details.items[0].display_name,
        "ocid": resource_details.items[0].identifier,
        "resource_type": resource_details.items[0].resource_type
    },
    "associated_resources": []
}

# Add associated resources to the JSON structure
for resource_summary in search_results:
    if resource_details.items[0].resource_type != resource_summary.resource_type:
        secondary_search_results = search_resource_by_ocid(resource_summary.identifier)
        for second_resource_summary in secondary_search_results:
            associated_resource_data = {
                "display_name": second_resource_summary.display_name,
                "compartment_id": second_resource_summary.compartment_id,
                "ocid": second_resource_summary.identifier,
                "resource_type": second_resource_summary.resource_type
            }
            resource_data["associated_resources"].append(associated_resource_data)

# Convert to JSON and log
resource_data_json = json.dumps(resource_data, indent=4)
logging.info(resource_data_json)

# Write the JSON data to a file
with open(r'C:\Security\Blogs\oci-config-history\logs\final_logfile.json', 'w') as log_file:
    log_file.write(resource_data_json)
