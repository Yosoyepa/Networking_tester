from datetime import datetime
import sqlite3
import logging
from pathlib import Path
import json # For storing complex dicts as text
from ..utils.config_manager import ConfigManager

logger = logging.getLogger(__name__)

class DatabaseHandler:
    def __init__(self):
        self.is_enabled = ConfigManager.get('storage.database_enabled', False)
        db_name_str = ConfigManager.get('storage.database_name', 'data/analysis_results.db')
        
        project_root = Path(__file__).resolve().parent.parent.parent
        self.db_path = project_root / db_name_str
        
        if self.is_enabled:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = None
            self.cursor = None
            self._connect()
            self._create_table()
            logger.info(f"DatabaseHandler initialized. DB: {self.db_path}")
        else:
            logger.info("DatabaseHandler is disabled by configuration.")


    def _connect(self):
        if not self.is_enabled: return
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            logger.debug(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database {self.db_path}: {e}")
            self.is_enabled = False # Disable if connection fails

    def _create_table(self):
        if not self.is_enabled or not self.cursor: return
        try:
            # A very generic table. Consider more specific columns or JSONB if using PostgreSQL.
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS packet_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capture_timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    summary TEXT,
                    full_analysis_json TEXT,
                    anomaly_detected BOOLEAN DEFAULT FALSE
                )
            """)
            self.conn.commit()
            logger.debug("Table 'packet_analysis' ensured to exist.")
        except sqlite3.Error as e:
            logger.error(f"Error creating table 'packet_analysis': {e}")

    def save_analysis(self, analysis_data):
        """
        Saves a single packet's analysis data to the database.
        analysis_data is expected to be the rich dictionary produced by the engine.
        """
        if not self.is_enabled or not self.cursor: return

        # Extract common fields, adapt as your analysis_data structure evolves
        ts = analysis_data.get('capture_timestamp', datetime.now().isoformat()) # Ensure timestamp
        protocol_details = analysis_data.get('protocol_details', {})
        src_ip = protocol_details.get('src_ip')
        dst_ip = protocol_details.get('dst_ip')
        protocol_name = protocol_details.get('protocol') # e.g., TCP, UDP
        
        # Use a summary if available, otherwise generate one or stringify
        summary = analysis_data.get('packet_summary', {}).get('summary_line', 'N/A')
        if isinstance(summary, dict): # if packet_summary itself is the summary
            summary = summary.get('summary_line', json.dumps(summary))


        full_analysis_json = json.dumps(analysis_data, default=str)
        
        anomaly_analysis = analysis_data.get('anomaly_analysis', {})
        anomaly_detected = bool(anomaly_analysis.get('detected_anomalies'))


        try:
            self.cursor.execute("""
                INSERT INTO packet_analysis 
                (capture_timestamp, source_ip, destination_ip, protocol, summary, full_analysis_json, anomaly_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ts, src_ip, dst_ip, protocol_name, summary, full_analysis_json, anomaly_detected))
            self.conn.commit()
            logger.debug(f"Saved analysis for {src_ip}->{dst_ip} ({protocol_name}) to DB.")
        except sqlite3.Error as e:
            logger.error(f"Error saving analysis to database: {e}")
        except Exception as e: # Catch other potential errors during data extraction
            logger.error(f"Unexpected error preparing data for DB: {e}. Data: {analysis_data}")


    def close(self):
        if self.is_enabled and self.conn:
            self.conn.close()
            logger.debug("Database connection closed.")
