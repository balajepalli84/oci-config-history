import oci
import datetime
import time
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
logging_mgmt_client = oci.logging.LoggingManagementClient(config)
logging_client = oci.loggingingestion.LoggingClient(config)
kms_vault_client = oci.key_management.KmsVaultClient(config)


def wait_for_log_group_active(log_group_id, max_wait_seconds=60, wait_interval_seconds=5):
    elapsed_time = 0
    while elapsed_time < max_wait_seconds:
        group = logging_mgmt_client.get_log_group(log_group_id).data
        if group.lifecycle_state == "ACTIVE":
            return log_group_id
        time.sleep(wait_interval_seconds)
        elapsed_time += wait_interval_seconds
    raise TimeoutError(f"Log Group {log_group_id} did not become ACTIVE in time.")


def wait_for_log_stream_active(log_group_id, log_display_name, max_wait_seconds=60, wait_interval_seconds=5):
    elapsed_time = 0
    while elapsed_time < max_wait_seconds:
        logs = logging_mgmt_client.list_logs(
            log_group_id=log_group_id,
            display_name=log_display_name
        ).data
        if logs and logs[0].lifecycle_state == "ACTIVE":
            return logs[0].id
        time.sleep(wait_interval_seconds)
        elapsed_time += wait_interval_seconds
    raise TimeoutError(f"Log Stream '{log_display_name}' did not become ACTIVE in time.")


def get_or_create_log_group():
    groups = logging_mgmt_client.list_log_groups(COMPARTMENT_ID, display_name=LOG_GROUP_NAME).data
    if groups:
        return groups[0].id

    group = logging_mgmt_client.create_log_group(
        oci.logging.models.CreateLogGroupDetails(
            compartment_id=COMPARTMENT_ID,
            display_name=LOG_GROUP_NAME
        )
    ).data

    # Wait and poll every 30 seconds until lifecycle_state is ACTIVE
    max_wait_seconds = 300  # 5 minutes max wait
    waited_seconds = 0

    while waited_seconds < max_wait_seconds:
        time.sleep(30)
        waited_seconds += 30
        groups = logging_mgmt_client.list_log_groups(COMPARTMENT_ID, display_name=LOG_GROUP_NAME).data
        if groups and groups[0].lifecycle_state == "ACTIVE":
            return groups[0].id
        print(f"Waiting for Log Group '{LOG_GROUP_NAME}' to become ACTIVE...")

    raise TimeoutError("Log Group did not become ACTIVE within expected time.")

def get_or_create_log_stream(log_group_id):
    streams = logging_mgmt_client.list_logs(log_group_id, display_name=LOG_STREAM_NAME).data
    if streams:
        return streams[0].id

    stream = logging_mgmt_client.create_log(
        log_group_id,
        oci.logging.models.CreateLogDetails(
            display_name=LOG_STREAM_NAME,
            log_type="CUSTOM"
        )
    ).data

    # Wait and poll every 30 seconds until lifecycle_state is ACTIVE
    max_wait_seconds = 300  # 5 minutes max wait
    waited_seconds = 0

    while waited_seconds < max_wait_seconds:
        time.sleep(30)
        waited_seconds += 30
        streams = logging_mgmt_client.list_logs(log_group_id, display_name=LOG_STREAM_NAME).data
        if streams and streams[0].lifecycle_state == "ACTIVE":
            return streams[0].id
        print(f"Waiting for Log Stream '{LOG_STREAM_NAME}' to become ACTIVE...")

    raise TimeoutError("Log Stream did not become ACTIVE within expected time.")



def log_event(log_stream_id, message, start_time=None):
    current_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    
    # Calculate runtime if start_time is provided
    runtime_info = ""
    if start_time:
        elapsed_seconds = (datetime.datetime.utcnow() - start_time).total_seconds()
        runtime_info = f"\nRuntime (seconds): {elapsed_seconds}"

    # Prepend timestamp and runtime to the message
    final_message = f"ExecutedTime: {current_time.isoformat()}Z{runtime_info}\n{message}"

    log_entry = oci.loggingingestion.models.PutLogsDetails(
        specversion="1.0",
        log_entry_batches=[
            oci.loggingingestion.models.LogEntryBatch(
                entries=[
                    oci.loggingingestion.models.LogEntry(
                        data=final_message,
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
