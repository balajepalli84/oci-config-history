import io
import json
import logging
import oci
import oracledb
import zipfile
import os
import traceback
from datetime import datetime


from fdk import response

# CONFIGURATION: Set these for your environment
WALLET_BUCKET_NAME = "secrets"
WALLET_OBJECT_NAME = "Wallet.zip"
WALLET_PASSWORD = ""
WALLET_DIR = "/tmp/wallet"
DB_USER = "admin"
DB_PASSWORD = ""
DB_DSN = ""


def download_and_extract_wallet(logger):
    logger.debug("Starting wallet download process")
    try:       
        Signer = oci.auth.signers.get_resource_principals_signer() 
        object_storage = oci.object_storage.ObjectStorageClient(config={}, signer=Signer)
        namespace = object_storage.get_namespace().data
        logger.debug(f"Object storage namespace: {namespace}")
        logger.debug(f"Attempting to download wallet from bucket '{WALLET_BUCKET_NAME}', object '{WALLET_OBJECT_NAME}'")
        wallet_obj = object_storage.get_object(namespace, WALLET_BUCKET_NAME, WALLET_OBJECT_NAME)
        wallet_path = "/tmp/adb_wallet.zip"
        with open(wallet_path, "wb") as f:
            f.write(wallet_obj.data.content)
        logger.debug(f"Wallet downloaded to {wallet_path}")
        with zipfile.ZipFile(wallet_path, 'r') as zip_ref:
            zip_ref.extractall(WALLET_DIR)
        logger.debug(f"Wallet extracted to {WALLET_DIR}")
    except Exception as e:
        logger.error(f"Failed to download or extract wallet: {str(e)}")
        logger.debug(traceback.format_exc())
        raise

def get_db_connection(logger):
    logger.debug("Attempting to connect to Oracle DB using wallet")
    try:
        conn = oracledb.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            dsn=DB_DSN,
            config_dir=WALLET_DIR,
            wallet_location=WALLET_DIR,
            wallet_password=WALLET_PASSWORD
        )
        logger.debug("Database connection established successfully")
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        logger.debug(traceback.format_exc())
        raise

def insert_audit_log(conn, entry, logger, entry_index):
    sql = """
    INSERT INTO oci_audit_logs (
        TENANT_ID,
        PRINCIPAL_NAME,
        COMPARTMENT_ID,
        EVENT_TYPE,
        EVENT_NAME,
        PRINCIPAL_ID,
        IP_ADDRESS,
        LOG_TYPE,
        LOG_TIME,
        COMPARTMENT_NAME
    ) VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10)
    """
    log_time_str = entry.get("time", None)
    try:
        log_time = datetime.strptime(log_time_str, "%Y-%m-%dT%H:%M:%S.%fZ") if log_time_str else datetime.utcnow()
    except ValueError:
        try:
            log_time = datetime.strptime(log_time_str, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            logger.warning(f"[Entry {entry_index}] Invalid timestamp format: {log_time_str}. Using current UTC time.")
            log_time = datetime.utcnow()

    data_block = entry.get("data", {})
    identity = data_block.get("identity", {})

    values = (
        identity.get("tenantId", "N/A"),            # TENANT_ID
        identity.get("principalName", "N/A"),       # PRINCIPAL_NAME
        data_block.get("compartmentId", "N/A"),     # COMPARTMENT_ID
        entry.get("type", "N/A"),                   # EVENT_TYPE
        data_block.get("eventName", "N/A"),         # EVENT_NAME
        identity.get("principalId", "N/A"),         # PRINCIPAL_ID
        identity.get("ipAddress", "N/A"),           # IP_ADDRESS
        entry.get("logType", "N/A"),                # LOG_TYPE
        log_time,                   # LOG_TIME
        data_block.get("compartmentName", "N/A")    # COMPARTMENT_NAME
    )

    logger.debug(f"[Entry {entry_index}] SQL: {sql.strip()}")
    logger.debug(f"[Entry {entry_index}] Values: {values}")

    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, values)
        conn.commit()
        logger.info(f"[Entry {entry_index}] Successfully inserted into oci_audit_logs")
    except Exception as e:
        logger.error(f"[Entry {entry_index}] Failed to insert into oci_audit_logs: {str(e)}")
        logger.debug(traceback.format_exc())
        # logger.debug(f"[Entry {entry_index}] Entry data: {json.dumps(entry, indent=2)}")
        raise




def handler(ctx, data: io.BytesIO = None):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.info("Function start")

    try:
        logger.debug("Checking if wallet directory exists")
        if not os.path.exists(WALLET_DIR):
            logger.debug(f"Wallet directory {WALLET_DIR} does not exist, creating it")
            os.makedirs(WALLET_DIR, exist_ok=True)
            download_and_extract_wallet(logger)
        else:
            logger.debug(f"Wallet directory {WALLET_DIR} already exists")

        logger.debug("Establishing database connection")
        conn = get_db_connection(logger)

        logger.debug("Reading input data from function")
        raw_data = data.getvalue()
        #logger.debug(f"Raw input data (bytes): {raw_data[:1000]}")  # Limit log size

        try:
            logentries = json.loads(raw_data)
            logger.debug("JSON loaded successfully")
        except Exception as jde:
            logger.error(f"JSON decode error: {str(jde)}")
            logger.debug(traceback.format_exc())
            logger.debug(f"Raw data: {raw_data.decode('utf-8', errors='replace')}")
            raise

        if not isinstance(logentries, list):
            logger.debug("Input is a single JSON object, wrapping in a list")
            logentries = [logentries]

        logger.info(f"Processing {len(logentries)} log entries")
        for i, entry in enumerate(logentries):
            logger.debug(f"Processing entry {i + 1}")
            try:
                insert_audit_log(conn, entry, logger, i + 1)
            except Exception as entry_error:
                logger.error(f"Error inserting entry {i + 1}: {str(entry_error)}")
                logger.debug(traceback.format_exc())
                #logger.debug(f"Entry data: {json.dumps(entry, indent=2)}")

        logger.debug("Closing database connection")
        conn.close()
        logger.info("Function completed successfully")

    except Exception as e:
        logger.error(f"Unexpected error in handler: {str(e)}")
        logger.debug(traceback.format_exc())
        raise
