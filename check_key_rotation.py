import oci
import datetime
from dateutil import parser
from datetime import timezone

# Load OCI Configuration
config = oci.config.from_file()
TENANCY_ID = config["tenancy"]
COMPARTMENT_ID = TENANCY_ID

LOG_GROUP_NAME = "OCI_Config_Monitor"
LOG_STREAM_NAME = "Key_Rotation_Check"

# OCI Clients
search_client = oci.resource_search.ResourceSearchClient(config)
base_logging_client = oci.logging.LoggingManagementClient(config)
logging_composite_client = oci.logging.LoggingManagementClientCompositeOperations(base_logging_client)  # Correct composite client
logging_client = oci.loggingingestion.LoggingClient(config)
kms_vault_client = oci.key_management.KmsVaultClient(config)


def get_or_create_log_group():
    groups = base_logging_client.list_log_groups(
        compartment_id=COMPARTMENT_ID, 
        display_name=LOG_GROUP_NAME
    ).data

    if groups:
        group = groups[0]
        if group.lifecycle_state == "ACTIVE":
            print(f"Log group {LOG_GROUP_NAME} already exists with ID: {group.id}",flush=True)
            return group.id
            
        response = oci.wait_until(
            base_logging_client,
            base_logging_client.get_log_group(group.id),
            evaluate_response=lambda r: r.data.lifecycle_state == 'ACTIVE',
            max_wait_seconds=30
        )
        return response.data.id

    # Create new log group with composite client waiter
    create_details = oci.logging.models.CreateLogGroupDetails(
        compartment_id=COMPARTMENT_ID,
        display_name=LOG_GROUP_NAME
    )
    print(f"Creating log group {LOG_GROUP_NAME}...",flush=True)
    response = logging_composite_client.create_log_group_and_wait_for_state(
        create_details,
        wait_for_states=['ACTIVE'],
        waiter_kwargs={'max_wait_seconds': 300}
    )
    return response.data.id

def get_or_create_log_stream(log_group_id):
    streams = base_logging_client.list_logs(
        log_group_id=log_group_id, 
        display_name=LOG_STREAM_NAME
    ).data

    if streams:
        stream = streams[0]
        if stream.lifecycle_state == "ACTIVE":
            return stream.id
        response = oci.wait_until(
            base_logging_client,
            base_logging_client.get_log(stream.id),
            evaluate_response=lambda r: r.data.lifecycle_state == 'ACTIVE',
            max_wait_seconds=300
        )
        return response.data.id

    # Create new log stream with composite client waiter
    create_details = oci.logging.models.CreateLogDetails(
        display_name=LOG_STREAM_NAME,
        log_type="CUSTOM"
    )
    print(f"Creating log stream {LOG_STREAM_NAME}...",flush=True)
    response = logging_composite_client.create_log_and_wait_for_state(
        log_group_id,
        create_details,
        wait_for_states=['ACTIVE'],
        waiter_kwargs={'max_wait_seconds': 30}
    )
    return response.data.id


def log_event(log_stream_id, message):
    current_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    log_entry = oci.loggingingestion.models.PutLogsDetails(
        specversion="1.0",
        log_entry_batches=[
            oci.loggingingestion.models.LogEntryBatch(
                entries=[
                    oci.loggingingestion.models.LogEntry(
                        data=message,
                        id=str(current_time.timestamp()),
                        time=current_time
                    )
                ],
                source="KeyRotationChecker",
                type="CUSTOM",
                defaultlogentrytime=current_time,
                subject="KeyRotationCheck"
            )
        ]
    )
    logging_client.put_logs(log_stream_id, log_entry)


def get_key_version_creation_time(key_ocid, key_version_ocid, vault_id):
    vault_resp = kms_vault_client.get_vault(vault_id).data
    vault_management_endpoint = vault_resp.management_endpoint

    kms_mgmt_client = oci.key_management.KmsManagementClient(
        config, service_endpoint=vault_management_endpoint
    )

    version = kms_mgmt_client.get_key_version(key_ocid, key_version_ocid).data
    return version.time_created


def check_key_rotation():
    six_months_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=180)).replace(tzinfo=datetime.timezone.utc)

    response = search_client.search_resources(
        search_details=oci.resource_search.models.StructuredSearchDetails(
            query="query key resources return allAdditionalFields where lifecycleState = 'ENABLED'",
            type="Structured"
        )
    )

    log_group_id = get_or_create_log_group()
    log_stream_id = get_or_create_log_stream(log_group_id)

    for item in response.data.items:
        key_ocid = item.identifier
        additional_details = item.additional_details

        current_key_version_ocid = additional_details.get("currentKeyVersion")
        vault_id = additional_details.get("vaultId")

        if not current_key_version_ocid or not vault_id:
            print(f"Missing currentKeyVersion or vaultId for key: {key_ocid}, skipping...")
            continue

        try:
            version_created_time = get_key_version_creation_time(
                key_ocid, current_key_version_ocid, vault_id
            )

            if version_created_time.tzinfo is None:
                version_created_time = version_created_time.replace(tzinfo=datetime.timezone.utc)

        except Exception as e:
            print(f"Error fetching version info for key: {key_ocid} - {str(e)}")
            continue

        if version_created_time < six_months_ago:
            message = (
                f"Key Rotation Alert:\n"
                f"Key OCID: {key_ocid}\n"
                f"Current Key Version: {current_key_version_ocid}\n"
                f"Compartment: {item.compartment_id}\n"
                f"Key Created: {item.time_created}\n"
                f"Current Key Version Created: {version_created_time}\n"
                f"Additional Details: {additional_details}"
            )
            log_event(log_stream_id, message)
            print(f"Logged rotation alert for key: {key_ocid}")
        else:
            print(f"Key {key_ocid} is compliant. Last rotation: {version_created_time}")


if __name__ == "__main__":
    check_key_rotation()
